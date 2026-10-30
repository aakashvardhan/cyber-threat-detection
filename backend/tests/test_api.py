import json

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from app.explain import LLMClient, Redactor, parse_llm_json
from app.main import create_app
from conftest import API_KEY, ATTACKER, wait_ready, window


def iso(i):
    return window(i).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------- auth
def test_requests_without_key_are_rejected(make_settings):
    with TestClient(create_app(make_settings())) as anonymous:
        for method, url in [("post", "/detect"), ("get", "/incidents"), ("get", "/metrics"), ("get", "/incidents/INC-0001")]:
            response = getattr(anonymous, method)(url)
            assert response.status_code == 401
            assert response.json() == {"detail": "Missing or wrong X-API-Key"}


# ---------------------------------------------------------------- /detect
def test_detect_steps_through_windows_and_is_idempotent(client):
    first = client.post("/detect").json()
    assert first["window_start"] == iso(0) and first["window_index"] == 1 and first["window_count"] == 12
    assert first["next_window_start"] == iso(1) and first["already_processed"] is False
    assert first["events"] == 4 and first["attack_edges"] == 0

    client.post("/detect", json={"window_start": iso(1)})
    third = client.post("/detect", json={"window_start": iso(2)}).json()
    assert third["attack_edges"] == 6 and len(third["new_incident_ids"]) == 1

    again = client.post("/detect", json={"window_start": iso(2)}).json()
    assert again["already_processed"] is True
    assert again["new_incident_ids"] == third["new_incident_ids"]
    assert len(client.get("/incidents").json()["incidents"]) == 1


def test_timestamp_formats_are_normalised(client):
    a = client.post("/detect", json={"window_start": "2025-05-30T16:00:00Z"}).json()
    b = client.post("/detect", json={"window_start": "2025-05-30T16:00:00+00:00"}).json()
    c = client.post("/detect", json={"window_start": "2025-05-30T18:00:00+02:00"}).json()
    assert a["window_index"] == b["window_index"] == c["window_index"] == 1
    assert b["already_processed"] and c["already_processed"]


def test_unknown_window_is_400_and_end_of_replay_is_409(client):
    assert client.post("/detect", json={"window_start": "2020-01-01T00:00:00Z"}).status_code == 400
    for _ in range(12):
        assert client.post("/detect").status_code == 200
    response = client.post("/detect")
    assert response.status_code == 409 and "reset" in response.json()["detail"]
    restarted = client.post("/detect", json={"reset": True}).json()
    assert restarted["window_index"] == 1 and restarted["already_processed"] is False


def test_bad_body_is_422(client):
    assert client.post("/detect", json={"window_start": "not-a-date"}).status_code == 422


def test_reset_is_atomic(make_settings):
    app = create_app(make_settings())
    with TestClient(app, headers={"X-API-Key": API_KEY}) as c:
        c.post("/detect", json={"window_start": iso(2)})
        assert len(c.get("/incidents").json()["incidents"]) == 1

        detector = app.state.app_state.detector
        original = detector.predict
        detector.predict = lambda rows: (_ for _ in ()).throw(RuntimeError("model crashed"))
        with pytest.raises(RuntimeError):
            c.post("/detect", json={"window_start": iso(3), "reset": True})
        detector.predict = original
        assert len(c.get("/incidents").json()["incidents"]) == 1        # old state kept

        c.post("/detect", json={"window_start": iso(0), "reset": True})
        assert c.get("/incidents").json()["incidents"] == []


# ---------------------------------------------------------------- incidents
def test_grouping_joins_within_30_minutes_and_splits_after(client):
    for i in range(12):
        client.post("/detect", json={"window_start": iso(i)})
    incidents = client.get("/incidents").json()["incidents"]
    assert len(incidents) == 2                                    # windows 2-4 joined; window 11 is 35 min later
    first, second = sorted(incidents, key=lambda x: x["first_seen"])
    assert first["edge_count"] == 18 and first["target_count"] == 6
    assert first["first_seen"] == iso(2) and first["last_seen"] == iso(4)
    assert second["first_seen"] == iso(11)
    assert first["source_ip"] == ATTACKER and first["technique_id"] == "T1190"
    assert first["technique_name"] == "Exploit Public-Facing Application" and first["tactic"] == "Initial Access"
    assert first["severity"] == "high" and first["low_confidence"] is False
    assert len(first["edges_preview"]) == 3 and first["edges_preview"][0]["port"] == 80
    assert first["edges_preview"][0]["service"] == "http"


def test_incident_list_shape(client):
    client.post("/detect", json={"window_start": iso(2)})
    body = client.get("/incidents").json()
    assert body["replay"] == {"window_start": iso(2), "window_index": 3, "window_count": 12,
                              "first_window_start": iso(0), "last_window_start": iso(11), "day_starts": [iso(0)]}
    assert body["primary_model"] == "model_1" and body["threshold"] == 0.5
    assert body["windows"] == [{"window_start": iso(2), "events": 10, "attack_edges": 6, "high_confidence_edges": 6}]


def test_incident_detail_with_fallback_explanation(client):
    client.post("/detect", json={"window_start": iso(2)})
    incident_id = client.get("/incidents").json()["incidents"][0]["incident_id"]
    detail = wait_ready(client, incident_id)

    assert detail["verdict"] == "attack"
    assert detail["mitre_candidates"][0] == {"rank": 1, "technique_id": "T1190",
                                             "name": "Exploit Public-Facing Application", "confidence": 0.72}
    assert detail["tactic_prediction"] == {"label": "Initial Access", "confidence": 0.81}
    assert len(detail["edges"]) == 6
    features = detail["edges"][0]["traffic_features"]
    assert features["connection_count"] == 30 and features["dominant_destination_port"] == 80
    assert features["dominant_zeek_service"] == "http"

    evidence = detail["evidence"]
    assert evidence[0]["evidence_id"] == "E1" and evidence[0]["source"] == "mitre" and evidence[0]["ref"] == "T1190"
    assert "(Citation" not in evidence[0]["text"]
    assert any(e["source"] == "procedure" and e["ref"] == "C0001" for e in evidence)
    assert detail["cve_status"] == "not_applicable"           # no cve_chunks.jsonl
    assert detail["retrieval_trace"]["sources"][0] == {"source": "mitre", "returned": 1}

    explanation = detail["explanation"]
    assert explanation["status"] == "ready" and explanation["mode"] == "fallback" and explanation["stale"] is False
    assert explanation["based_on_edge_count"] == 6
    cited = {c for s in explanation["sentences"] for c in s["citations"]}
    assert cited <= {e["evidence_id"] for e in evidence} and "E1" in cited
    assert 0 < explanation["groundedness"] <= 1
    assert detail["mitigations"] == [{"mitigation_id": "M1050", "name": "Exploit Protection"},
                                     {"mitigation_id": "M1030", "name": "Network Segmentation"}]
    assert detail["models"][0]["model"] == "model_1"


def test_explanation_goes_stale_and_regenerates(client):
    client.post("/detect", json={"window_start": iso(2)})
    incident_id = client.get("/incidents").json()["incidents"][0]["incident_id"]
    wait_ready(client, incident_id)
    client.post("/detect", json={"window_start": iso(3)})          # incident grows
    stale = client.get(f"/incidents/{incident_id}").json()
    assert stale["explanation"]["stale"] is True and stale["edge_count"] == 12
    client.get(f"/incidents/{incident_id}", params={"refresh_explanation": True})
    fresh = wait_ready(client, incident_id)
    assert fresh["explanation"]["stale"] is False and fresh["explanation"]["based_on_edge_count"] == 12


def test_missing_incident_is_404(client):
    response = client.get("/incidents/INC-9999")
    assert response.status_code == 404 and "INC-9999" in response.json()["detail"]
    assert client.patch("/incidents/INC-9999", json={"status": "closed"}).status_code == 404


def test_related_incidents_share_an_ip_within_an_hour(client):
    for i in range(12):
        client.post("/detect", json={"window_start": iso(i)})
    first, second = sorted(client.get("/incidents").json()["incidents"], key=lambda x: x["first_seen"])
    detail = client.get(f"/incidents/{first['incident_id']}").json()
    assert detail["related_incident_ids"] == [second["incident_id"]]


# ---------------------------------------------------------------- PATCH
def test_patch_updates_fields_and_logs_activity(client):
    client.post("/detect", json={"window_start": iso(2)})
    incident_id = client.get("/incidents").json()["incidents"][0]["incident_id"]
    summary = client.patch(f"/incidents/{incident_id}", json={
        "status": "confirmed", "technique_override": "T1595", "note": "Escalating.", "mitigations_applied": ["M1050"]}).json()
    assert summary["status"] == "confirmed" and summary["technique_override"] == "T1595"
    assert summary["technique_id"] == "T1595" and summary["technique_name"] == "Active Scanning"
    assert summary["mitigations_applied"] == ["M1050"]

    summary = client.patch(f"/incidents/{incident_id}", json={"note": "Only a note."}).json()
    assert summary["status"] == "confirmed" and summary["technique_override"] == "T1595"   # untouched fields kept
    summary = client.patch(f"/incidents/{incident_id}", json={"technique_override": None}).json()
    assert summary["technique_override"] is None and summary["technique_id"] == "T1190"

    activity = client.get(f"/incidents/{incident_id}").json()["activity"]
    assert [a["status"] for a in activity] == ["confirmed", "confirmed", "confirmed"]
    assert activity[0]["note"] == "Escalating." and activity[1]["note"] == "Only a note."
    assert client.patch(f"/incidents/{incident_id}", json={"status": "bogus"}).status_code == 422


# ---------------------------------------------------------------- /metrics
def test_metrics_returns_bundle_plus_knowledge_base(client):
    body = client.get("/metrics").json()
    assert body["primary_model"] == "model_1"
    assert {m["model"] for m in body["models"]} == {"model_1", "model_2", "model_3", "model_4", "model_5"}
    sources = {s["source"]: s for s in body["knowledge_base"]["sources"]}
    assert sources["mitre"]["items"] == 4 and sources["procedure"]["chunks"] == 3


# ---------------------------------------------------------------- research outputs
def test_precomputed_model_outputs_for_research_tab(make_settings, paths):
    with (paths / "model_outputs.jsonl").open("w") as handle:
        for t in range(6):
            for model, prob, label in [("model_2", 0.44, "normal"), ("model_4", 0.91, "attack")]:
                handle.write(json.dumps({"window_start": iso(2), "src_ip_zeek": ATTACKER,
                                         "dest_ip_zeek": f"143.88.5.{20 + t}", "model": model, "label": label,
                                         "attack_probability": prob, "technique_id": "T1595", "confidence": 0.38,
                                         "explanation_text": "LLM text" if model == "model_4" else None,
                                         "groundedness": 0.85 if model == "model_4" else None}) + "\n")
    with TestClient(create_app(make_settings(model_outputs=paths / "model_outputs.jsonl")),
                    headers={"X-API-Key": API_KEY}) as c:
        c.post("/detect", json={"window_start": iso(2)})
        incident_id = c.get("/incidents").json()["incidents"][0]["incident_id"]
        models = {m["model"]: m for m in c.get(f"/incidents/{incident_id}").json()["models"]}
        assert set(models) == {"model_1", "model_2", "model_4"}
        assert models["model_2"]["label"] == "normal" and models["model_4"]["explanation_text"] == "LLM text"
        assert models["model_4"]["groundedness"] == 0.85


# ---------------------------------------------------------------- LLM path
class FakeLLM(LLMClient):
    def __init__(self, settings, reply):
        super().__init__(settings)
        self.reply, self.prompts = reply, []

    @property
    def enabled(self):
        return True

    def chat(self, user_prompt):
        self.prompts.append(user_prompt)
        return self.reply


def test_llm_explanation_with_redaction_and_citation_filtering(make_settings):
    settings = make_settings(llm_provider="local", llm_model="finetuned", redact_ips=True)
    app = create_app(settings)
    reply = json.dumps({"sentences": [
        {"text": "host-A made many HTTP connections to web servers.", "citations": ["E1", "E99"]},
        {"text": "The attacker likely wanted a foothold.", "citations": []}],
        "next_steps": ["Block host-A at the firewall"]})
    fake = FakeLLM(settings, "Sure! " + reply)
    app.state.app_state.explanations.client = fake
    with TestClient(app, headers={"X-API-Key": API_KEY}) as c:
        c.post("/detect", json={"window_start": iso(2)})
        incident_id = c.get("/incidents").json()["incidents"][0]["incident_id"]
        explanation = wait_ready(c, incident_id)["explanation"]
    assert ATTACKER not in fake.prompts[0] and "host-A" in fake.prompts[0]
    assert explanation["mode"] == "llm" and explanation["model"] == "finetuned"
    assert explanation["sentences"][0]["text"].startswith(ATTACKER)
    assert explanation["sentences"][0]["citations"] == ["E1"]           # E99 is not real evidence
    assert explanation["next_steps"] == [f"Block {ATTACKER} at the firewall"]
    assert explanation["groundedness"] == 0.5


def test_llm_failure_falls_back_to_evidence_only(make_settings):
    settings = make_settings(llm_provider="local", llm_model="m")
    app = create_app(settings)
    app.state.app_state.explanations.client = FakeLLM(settings, "no json here")
    with TestClient(app, headers={"X-API-Key": API_KEY}) as c:
        c.post("/detect", json={"window_start": iso(2)})
        incident_id = c.get("/incidents").json()["incidents"][0]["incident_id"]
        explanation = wait_ready(c, incident_id)["explanation"]
    assert explanation["status"] == "ready" and explanation["mode"] == "fallback"
    assert "LLM unavailable" in explanation["message"]


def test_redactor_round_trip():
    r = Redactor(["143.88.6.11", "143.88.6.1"], enabled=True)
    hidden = r.hide("143.88.6.11 talked to 143.88.6.1 and 143.88.6.111")
    assert hidden == "host-A talked to host-B and 143.88.6.111"
    assert r.reveal(hidden) == "143.88.6.11 talked to 143.88.6.1 and 143.88.6.111"


def test_parse_llm_json_rejects_empty():
    with pytest.raises(ValueError):
        parse_llm_json("{}", {"E1"})


# ---------------------------------------------------------------- fallback detector + knowledge
def test_heuristic_detector_runs_end_to_end(make_settings):
    with TestClient(create_app(make_settings(primary_model="heuristic")), headers={"X-API-Key": API_KEY}) as c:
        body = c.post("/detect", json={"window_start": iso(2)}).json()
        assert body["attack_edges"] == 6
        listing = c.get("/incidents").json()
        assert listing["primary_model"] == "heuristic-fallback"
        assert listing["incidents"][0]["technique_id"] == "T1190"


def test_defense_evasion_falls_back_to_renamed_tactics(make_settings):
    from app.knowledge import KnowledgeBase
    kb = KnowledgeBase.load(make_settings().knowledge_dir)
    result = kb.retrieve("T1548", "Defense Evasion", "hide files evade defenders", top_k=5, min_score=0.0)
    assert result.evidence[0]["ref"] == "T1548"
    assert result.fallback_to_tactic is True
    assert any(e["level"] == "tactic" and e["ref"] == "G0002" for e in result.evidence)
