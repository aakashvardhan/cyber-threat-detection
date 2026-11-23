"""Fixes for the review findings on #60 (Docker) and #61 (DynamoDB)."""
import json
import os
import threading
import time
from pathlib import Path

import boto3
import pytest
from fastapi.testclient import TestClient
from moto import mock_aws

from app import store as store_module
from app.config import Settings
from app.main import create_app
from app.store import (MAX_ACTIVITY, DynamoStore, MemoryStore, SafeStore, apply_state, create_table, fingerprint,
                       load_store)
from conftest import API_KEY, wait_ready

TABLE = "threat-console-incidents-review"
REPO = Path(__file__).resolve().parents[2]


@pytest.fixture
def aws(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test", "AWS_DEFAULT_REGION": "us-west-2"}.items():
        monkeypatch.setenv(k, v)
    with mock_aws():
        yield


def replay(client):
    first = client.post("/detect", json={"reset": True})
    assert first.status_code == 200 and first.json()["window_index"] == 1 and not first.json()["already_processed"]
    while client.post("/detect", json={}).status_code == 200:
        pass
    return client.get("/incidents").json()["incidents"]


class Flaky:
    """A store that fails while `down` is True."""
    name = "flaky"

    def __init__(self):
        self.inner, self.down = MemoryStore(), False

    def load_all(self, model):
        if self.down:
            raise ConnectionError("down")
        return self.inner.load_all(model)

    def save(self, model, incident_id, fields):
        if self.down:
            raise ConnectionError("down")
        self.inner.save(model, incident_id, fields)

    def clear(self, model=None):
        return self.inner.clear(model)


# ---------------------------------------------------------------- #61: identity, failures, consistency, size
def test_saved_state_is_applied_only_to_the_same_incident(make_settings):
    app = create_app(make_settings())
    with TestClient(app, headers={"X-API-Key": API_KEY}) as client:
        incidents = replay(client)
        state = app.state.app_state
        incident = state.controller.state.incidents[incidents[0]["incident_id"]]
        other = state.controller.state.incidents[incidents[1]["incident_id"]]
        assert fingerprint(incident) != fingerprint(other)
        saved = {"fingerprint": fingerprint(other), "status": "closed"}
        assert apply_state(incident, saved) is False and incident.status != "closed"     # another incident's state
        assert apply_state(incident, {**saved, "fingerprint": fingerprint(incident)}) is True
        assert incident.status == "closed"


def test_failed_writes_are_kept_and_retried():
    flaky = Flaky()
    store = SafeStore(flaky)
    flaky.down = True
    store.save("m", "INC-1", {"status": "closed"})
    assert flaky.inner.load_all("m") == {} and store.pending
    assert store.load_all("m") == {"INC-1": {"status": "closed"}}         # a failed read returns the memory copy
    flaky.down = False
    store.save("m", "INC-2", {"status": "investigating"})                 # the next write flushes the earlier one
    assert set(flaky.inner.load_all("m")) == {"INC-1", "INC-2"} and not store.pending


def test_a_failed_read_does_not_wipe_state_on_reset(make_settings, monkeypatch):
    app = create_app(make_settings())
    with TestClient(app, headers={"X-API-Key": API_KEY}) as client:
        incident_id = replay(client)[0]["incident_id"]
        client.patch(f"/incidents/{incident_id}", json={"status": "closed"})
        store = app.state.app_state.store
        monkeypatch.setattr(store.inner, "load_all", lambda model: (_ for _ in ()).throw(ConnectionError("down")))
        replay(client)                                                   # Reset while the database is down
        assert client.get(f"/incidents/{incident_id}").json()["status"] == "closed"


def test_reads_are_strongly_consistent(aws):
    store = DynamoStore.connect(TABLE, "us-west-2")
    seen = []
    query = store.table.query
    store.table.query = lambda **kw: seen.append(kw) or query(**kw)
    store.load_all("graphsage")
    assert seen and all(kw.get("ConsistentRead") is True for kw in seen)


def test_activity_is_capped(make_settings):
    app = create_app(make_settings())
    with TestClient(app, headers={"X-API-Key": API_KEY}) as client:
        incident_id = replay(client)[0]["incident_id"]
        for i in range(MAX_ACTIVITY + 5):
            client.patch(f"/incidents/{incident_id}", json={"note": f"n{i}"})
        activity = client.get(f"/incidents/{incident_id}").json()["activity"]
        saved = app.state.app_state.store.load_all(app.state.app_state.detector.name)[incident_id]["activity"]
    assert len(activity) == MAX_ACTIVITY and activity[-1]["note"] == f"n{MAX_ACTIVITY + 4}"
    assert len(saved) == MAX_ACTIVITY


def test_oversized_item_is_refused_not_retried_forever(aws):
    store = SafeStore(DynamoStore.connect(TABLE, "us-west-2"))
    store.save("m", "INC-1", {"activity": ["x" * 400_000]})
    assert not store.pending and store.load_all("m")["INC-1"]["activity"][0].startswith("x")   # kept in memory


def test_connect_waits_for_dynamodb(aws, monkeypatch):
    calls = []
    real = store_module._ensure_table

    def flaky_ensure(client, name, create):
        calls.append(1)
        if len(calls) < 3:
            raise ConnectionError("starting")
        return real(client, name, create)

    monkeypatch.setattr(store_module, "_ensure_table", flaky_ensure)
    monkeypatch.setattr(store_module.time, "sleep", lambda s: None)
    assert DynamoStore.connect(TABLE, "us-west-2", wait_s=10).load_all("m") == {} and len(calls) == 3
    calls.clear()
    with pytest.raises(ConnectionError):
        DynamoStore.connect(TABLE, "us-west-2", wait_s=0)


def test_table_created_by_another_process_is_not_an_error(aws):
    client = boto3.client("dynamodb", region_name="us-west-2")
    create_table(client, TABLE)
    create_table(client, TABLE)                                          # ResourceInUseException is handled


def test_unknown_incident_store_is_a_configuration_error(monkeypatch):
    monkeypatch.setenv("API_KEY", "a-long-key")
    monkeypatch.setenv("INCIDENT_STORE", "dynamo")
    with pytest.raises(ValueError, match="INCIDENT_STORE"):
        Settings.from_env()
    with pytest.raises(ValueError, match="INCIDENT_STORE"):
        load_store(Settings(api_key="k" * 8, incident_store="dynamo"))


def test_retried_edit_is_recorded_once(make_settings):
    app = create_app(make_settings())
    with TestClient(app, headers={"X-API-Key": API_KEY}) as client:
        incident_id = replay(client)[0]["incident_id"]
        before = len(client.get(f"/incidents/{incident_id}").json()["activity"])
        for _ in range(2):
            r = client.patch(f"/incidents/{incident_id}", json={"note": "checked"}, headers={"Idempotency-Key": "edit-1"})
            assert r.status_code == 200
        client.patch(f"/incidents/{incident_id}", json={"note": "again"}, headers={"Idempotency-Key": "edit-2"})
        assert len(client.get(f"/incidents/{incident_id}").json()["activity"]) == before + 2


def test_edit_and_reset_do_not_interleave(make_settings):
    app = create_app(make_settings())
    with TestClient(app, headers={"X-API-Key": API_KEY}) as client:
        incident_id = replay(client)[0]["incident_id"]
        controller_lock = app.state.app_state.controller.lock
        controller_lock.acquire()                                        # a Reset is in progress
        done = threading.Event()
        threading.Thread(target=lambda: (client.patch(f"/incidents/{incident_id}", json={"status": "closed"}),
                                         done.set()), daemon=True).start()
        assert not done.wait(0.3)                                        # the edit waits for the Reset
        controller_lock.release()
        assert done.wait(5)


# ---------------------------------------------------------------- explanations: model, snapshot, Reset
class SlowLLM:
    enabled = True

    def __init__(self):
        self.go = threading.Event()
        self.calls = 0

    def chat(self, prompt, system=None):
        self.calls += 1
        self.go.wait(10)
        return json.dumps({"sentences": [{"text": "Scanning.", "citations": ["E1"]}], "next_steps": ["Block it."]})


def test_explanation_is_saved_under_the_model_that_produced_it(make_settings):
    app = create_app(make_settings(llm_provider="local", llm_model="m"))
    llm = SlowLLM()
    state = app.state.app_state
    state.explanations.client = llm
    with TestClient(app, headers={"X-API-Key": API_KEY}) as client:
        incident_id = replay(client)[0]["incident_id"]
        original = state.detector.name
        client.get(f"/incidents/{incident_id}")                           # starts the job
        state.explanations.model_name = lambda: "another-model"           # the live model switches meanwhile
        llm.go.set()
        state.explanations.wait_idle()
    saved = state.store.load_all(original).get(incident_id, {})
    assert saved.get("explanation", {}).get("status") == "ready"
    assert incident_id not in state.store.load_all("another-model")


def test_reset_during_a_job_reuses_its_result(make_settings):
    app = create_app(make_settings(llm_provider="local", llm_model="m"))
    llm = SlowLLM()
    state = app.state.app_state
    state.explanations.client = llm
    with TestClient(app, headers={"X-API-Key": API_KEY}) as client:
        incident_id = replay(client)[0]["incident_id"]
        assert client.get(f"/incidents/{incident_id}").json()["explanation"]["status"] == "generating"
        replay(client)                                                   # Reset re-creates the incident
        assert client.get(f"/incidents/{incident_id}").json()["explanation"]["status"] == "generating"
        llm.go.set()
        body = wait_ready(client, incident_id)
    assert body["explanation"]["status"] == "ready" and llm.calls == 1   # one job, not two


# ---------------------------------------------------------------- #60: configuration and images
def test_no_built_in_api_key(monkeypatch):
    monkeypatch.delenv("API_KEY", raising=False)
    with pytest.raises(ValueError, match="API_KEY"):
        Settings.from_env()
    monkeypatch.setenv("API_KEY", "short")
    with pytest.raises(ValueError, match="too short"):
        Settings.from_env()


def test_build_arguments_are_not_pasted_into_python():
    dockerfile = (REPO / "backend" / "Dockerfile").read_text()
    assert "${EMBED_MODEL}')" not in dockerfile and "${RERANK_MODEL}')" not in dockerfile
    assert 'sys.argv[1])\' "$EMBED_MODEL"' in dockerfile and 'sys.argv[1])\' "$RERANK_MODEL"' in dockerfile


def test_compose_publishes_only_the_console_and_keeps_the_key_server_side():
    import yaml
    compose = yaml.safe_load((REPO / "docker-compose.yml").read_text())
    services = compose["services"]
    for name in ("backend", "neo4j", "chroma", "dynamodb"):
        assert all(str(p).startswith("127.0.0.1:") for p in services[name].get("ports", [])), name
    frontend = services["frontend"]
    assert "args" not in frontend["build"]                               # nothing secret baked into the bundle
    assert "API_KEY" in frontend["environment"]                          # nginx adds it server-side
    backend_env = services["backend"]["environment"]
    assert "AWS_ACCESS_KEY_ID" not in backend_env and "AWS_SECRET_ACCESS_KEY" not in backend_env
    nginx = (REPO / "frontend" / "nginx" / "default.conf.template").read_text()
    assert "location /api/" in nginx and 'proxy_set_header X-API-Key "${API_KEY}"' in nginx
    assert "VITE_API_KEY=\n" in (REPO / "frontend" / "Dockerfile").read_text()


def test_local_dynamodb_needs_no_credentials_in_the_environment(monkeypatch):
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE", "AWS_SHARED_CREDENTIALS_FILE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent")
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent")
    seen = {}
    real = boto3.resource

    def capture(*args, **kwargs):
        seen.update(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(boto3, "resource", capture)
    with pytest.raises(Exception):                                       # nothing listens there; we only check the call
        DynamoStore.connect(TABLE, "us-west-2", endpoint="http://127.0.0.1:9", wait_s=0)
    assert seen.get("aws_access_key_id") == "local"


# ---------------------------------------------------------------- Neo4j: real database when one is available
@pytest.mark.skipif(not os.environ.get("NEO4J_TEST_URI"), reason="set NEO4J_TEST_URI (and NEO4J_TEST_PASSWORD) to run")
def test_load_into_real_neo4j(tmp_path):
    from neo4j import GraphDatabase

    from app.attack_graph import AttackGraph, Neo4jStore, NetworkXStore, load_into_neo4j
    from test_graph_rag import make_stix
    graph = AttackGraph.from_stix(make_stix(tmp_path / "stix.json"), None)
    graph.build_communities()
    driver = GraphDatabase.driver(os.environ["NEO4J_TEST_URI"],
                                  auth=("neo4j", os.environ.get("NEO4J_TEST_PASSWORD", "")))
    with driver.session() as session:
        load_into_neo4j(session, graph)
        nodes = session.run("MATCH (e:AttackEntity) RETURN count(e) AS n").single()["n"]
        edges = session.run("MATCH (:AttackEntity)-[r]->(:AttackEntity) RETURN count(r) AS n").single()["n"]
    assert nodes == len(graph.nodes) and edges == len(graph.edges)
    store = Neo4jStore(driver)
    seeds = [n for n, d in graph.nodes.items() if d["type"] == "Technique"][:1]
    assert set(store.local_subgraph(seeds).nodes) == set(NetworkXStore(graph).local_subgraph(seeds).nodes)
    driver.close()


# ---------------------------------------------------------------- Chroma: signature, partial builds, fallback
def _vector_sources():
    return {"cti": [{"id": "cti-1", "text": "The actor scanned ports", "metadata": {"technique_ids": ["T1595"]}},
                    {"id": "cti-2", "text": "Brute force on ssh", "metadata": {"technique_ids": ["T1110"]}}]}


def test_vector_index_is_rebuilt_when_text_changes_or_a_build_was_interrupted():
    chromadb = pytest.importorskip("chromadb")
    from app.vector_store import VectorStore
    from test_rag import fake_embed
    calls = []

    def counting_embed(texts):
        calls.append(len(texts))
        return fake_embed(texts)

    client, sources = chromadb.EphemeralClient(), _vector_sources()
    VectorStore.from_sources(client, counting_embed, "fake", sources)
    VectorStore.from_sources(client, counting_embed, "fake", sources)
    assert len(calls) == 1                                                # reused: nothing changed
    sources["cti"][0]["text"] = "The actor scanned many ports"           # same ID, new text
    store = VectorStore.from_sources(client, counting_embed, "fake", sources)
    assert len(calls) == 2 and "many" in store.cols["cti"].get(ids=["cti-1"])["documents"][0]
    store.cols["cti"].delete(ids=["cti-2"])                              # as if the build stopped half-way
    assert VectorStore.from_sources(client, counting_embed, "fake", sources).cols["cti"].count() == 2
    assert len(calls) == 3


def test_chroma_server_failure_falls_back_to_the_local_index(tmp_path, monkeypatch):
    pytest.importorskip("chromadb")
    from app import vector_store
    from app.vector_store import VectorStore

    class FakeEncoder:
        def __init__(self, *a, **k):
            pass

        def encode(self, texts, **k):
            import numpy as np
            from test_rag import fake_embed
            return np.array(fake_embed(texts))

    import sentence_transformers
    monkeypatch.setattr(sentence_transformers, "SentenceTransformer", FakeEncoder)
    real = VectorStore.from_sources.__func__
    used = []

    def from_sources(cls, client, embed, model, sources):
        used.append(type(client).__name__)
        if len(used) == 1:
            raise RuntimeError("collection error on the server")
        return real(cls, client, embed, model, sources)

    monkeypatch.setattr(VectorStore, "from_sources", classmethod(from_sources))
    import chromadb
    monkeypatch.setattr(chromadb, "HttpClient", lambda **k: chromadb.EphemeralClient())
    kdir = tmp_path / "knowledge"
    kdir.mkdir()
    (kdir / "cti_chunks.jsonl").write_text("\n".join(json.dumps(c) for c in _vector_sources()["cti"]))
    store = VectorStore.load(kdir, tmp_path / "chroma", "fake", host="chroma", port=8000)
    assert store is not None and len(used) == 2                          # server failed, local index used
    assert (tmp_path / "chroma").exists()


def test_compose_does_not_block_the_api_on_optional_stores():
    import yaml
    deps = yaml.safe_load((REPO / "docker-compose.yml").read_text())["services"]["backend"]["depends_on"]
    assert all(d["condition"] == "service_started" for d in deps.values())
    assert "--start-period=900s" in (REPO / "backend" / "Dockerfile").read_text()
