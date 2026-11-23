"""Incident store (SJSU-131): analyst edits and explanations survive a restart; DynamoDB tested with moto."""
import os

import boto3
import pytest
from fastapi.testclient import TestClient
from moto import mock_aws

from app.main import create_app
from app.store import DynamoStore, MemoryStore, SafeStore, create_table
from conftest import API_KEY, wait_ready

TABLE = "threat-console-incidents-test"


@pytest.fixture
def aws(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test", "AWS_DEFAULT_REGION": "us-west-2"}.items():
        monkeypatch.setenv(k, v)
    with mock_aws():
        yield


def run_replay(client):
    reset = client.post("/detect", json={"reset": True})
    # the reset must really restart the replay (otherwise the tests below would read the unchanged incident)
    assert reset.status_code == 200
    assert reset.json()["window_index"] == 1 and reset.json()["already_processed"] is False
    while client.post("/detect", json={}).status_code == 200:
        pass
    return client.get("/incidents").json()["incidents"]


def test_dynamo_store_round_trip(aws):
    store = DynamoStore.connect(TABLE, "us-west-2")            # creates the table
    store.save("graphsage", "INC-0001", {"status": "investigating", "activity": [{"note": "x", "score": 0.123456789}]})
    store.save("graphsage", "INC-0001", {"technique_override": "T1046"})       # merges, keeps the earlier fields
    store.save("hgt", "INC-0001", {"status": "closed"})
    saved = store.load_all("graphsage")
    assert saved == {"INC-0001": {"status": "investigating", "technique_override": "T1046",
                                  "activity": [{"note": "x", "score": 0.123456789}]}}   # floats stay exact
    assert set(store.load_all("hgt")) == {"INC-0001"}
    assert store.clear("hgt") == 1 and store.load_all("hgt") == {}


def test_missing_table_is_an_error_when_creation_is_off(aws):
    with pytest.raises(RuntimeError, match="does not exist"):
        DynamoStore.connect("no-such-table", "us-west-2", create=False)
    create_table(boto3.client("dynamodb", region_name="us-west-2"), "made-by-script")
    assert DynamoStore.connect("made-by-script", "us-west-2", create=False).load_all("m") == {}


def test_safe_store_never_raises():
    class Broken:
        name = "broken"

        def load_all(self, model):
            raise ConnectionError("down")

        def save(self, *a):
            raise ConnectionError("down")
    store = SafeStore(Broken())
    assert store.load_all("m") == {}
    store.save("m", "INC-1", {"status": "closed"})            # logged, not raised


def edit_and_explain(settings_factory, **extra):
    """Edit an incident and let its explanation finish; return (incident id, the app's store)."""
    app = create_app(settings_factory(**extra))
    with TestClient(app, headers={"X-API-Key": API_KEY}) as client:
        incident_id = run_replay(client)[0]["incident_id"]
        wait_ready(client, incident_id)
        client.patch(f"/incidents/{incident_id}", json={"status": "investigating", "note": "checked the source",
                                                       "mitigations_applied": ["M1031"]})
        return incident_id, app.state.app_state


def test_edits_and_explanation_survive_a_restart_with_dynamodb(aws, make_settings):
    extra = {"incident_store": "dynamodb", "dynamodb_table": TABLE}
    incident_id, first = edit_and_explain(make_settings, **extra)
    assert first.store.name == "dynamodb"
    explanation = first.controller.state.incidents[incident_id].explanation

    # a new backend process: same table, fresh memory
    with TestClient(create_app(make_settings(**extra)), headers={"X-API-Key": API_KEY}) as client:
        run_replay(client)
        body = client.get(f"/incidents/{incident_id}").json()
    assert body["status"] == "investigating"
    assert body["mitigations_applied"] == ["M1031"]
    assert body["activity"][-1]["note"] == "checked the source"
    assert body["explanation"]["status"] == "ready"
    assert [s["text"] for s in body["explanation"]["sentences"]] == [s["text"] for s in explanation["sentences"]]


def test_reset_keeps_saved_edits(make_settings):
    app = create_app(make_settings())
    with TestClient(app, headers={"X-API-Key": API_KEY}) as client:
        incident_id = run_replay(client)[0]["incident_id"]
        client.patch(f"/incidents/{incident_id}", json={"status": "closed"})
        old = app.state.app_state.controller.state
        run_replay(client)                                   # Reset in the console replays from the start
        assert app.state.app_state.controller.state is not old            # a fresh replay was built
        assert client.get(f"/incidents/{incident_id}").json()["status"] == "closed"
    assert app.state.app_state.store.name == "memory"


def test_unreachable_dynamodb_falls_back_to_memory(make_settings, monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "x")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "x")
    app = create_app(make_settings(incident_store="dynamodb", dynamodb_endpoint="http://127.0.0.1:9",
                                   dynamodb_wait_s=0))
    with TestClient(app, headers={"X-API-Key": API_KEY}) as client:
        assert run_replay(client)                            # the console still works
    assert app.state.app_state.store.name == "memory"


def test_chat_survives_a_restart_with_dynamodb(aws, make_settings):
    extra = {"incident_store": "dynamodb", "dynamodb_table": TABLE}
    with TestClient(create_app(make_settings(**extra)), headers={"X-API-Key": API_KEY}) as client:
        incident_id = run_replay(client)[0]["incident_id"]
        client.post(f"/incidents/{incident_id}/chat", json={"message": "Who uses this technique?"})
    with TestClient(create_app(make_settings(**extra)), headers={"X-API-Key": API_KEY}) as client:
        run_replay(client)
        messages = client.get(f"/incidents/{incident_id}/chat").json()["messages"]
    assert [m["role"] for m in messages] == ["user", "assistant"]
    assert messages[0]["text"] == "Who uses this technique?" and messages[1]["evidence"]
