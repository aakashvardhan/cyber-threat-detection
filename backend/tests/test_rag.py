"""Behaviour check and vector retrieval (RAG notebook pipeline)."""
import hashlib
import json

import numpy as np
import pandas as pd
import pytest
from fastapi.testclient import TestClient

from app.behavior import BehaviorSearch, TechniqueIndex, build_technique_docs, facts, incident_features, interpret
from app.main import create_app
from app.vector_store import VectorStore, is_lfs_pointer, procedures_from_stix, read_jsonl
from conftest import API_KEY, wait_ready, window


def iso(i):
    return window(i).strftime("%Y-%m-%dT%H:%M:%SZ")


def ap(sid, tid, name, desc):
    return {"type": "attack-pattern", "id": f"attack-pattern--{sid}", "name": name, "description": desc,
            "external_references": [{"source_name": "mitre-attack", "external_id": tid}]}


@pytest.fixture
def stix(tmp_path):
    objects = [
        ap("1", "T1110", "Brute Force", "Adversaries may use brute force techniques to gain access to accounts when "
           "passwords are unknown, by guessing passwords in repeated login attempts against SSH or RDP."),
        ap("2", "T1190", "Exploit Public-Facing Application", "Adversaries may exploit a weakness in an "
           "Internet-facing web server or web application to gain access."),
        ap("3", "T1595", "Active Scanning", "Adversaries may execute active reconnaissance scans, probing ports "
           "and hosts to discover services."),
        ap("4", "T1059", "Command and Scripting Interpreter", "Adversaries may abuse command interpreters."),
        {"type": "intrusion-set", "id": "intrusion-set--g1", "name": "Guessers",
         "external_references": [{"source_name": "mitre-attack", "external_id": "G9001", "url": "https://x/G9001"}]},
        {"type": "relationship", "id": "relationship--aaaa-1", "relationship_type": "uses", "source_ref": "intrusion-set--g1",
         "target_ref": "attack-pattern--1", "description": "Guessers brute forced SSH passwords on exposed servers.(Citation: R)"},
        {"type": "x-mitre-analytic", "id": "x-mitre-analytic--a1", "description": "Many short connections to many ports.",
         "x_mitre_log_source_references": [{"name": "NSM:Flow", "x_mitre_data_component_ref": "x"}]},
        {"type": "x-mitre-detection-strategy", "id": "x-mitre-detection-strategy--d1", "name": "Port scan detection",
         "x_mitre_analytic_refs": ["x-mitre-analytic--a1"]},
        {"type": "relationship", "id": "relationship--bbbb-2", "relationship_type": "detects",
         "source_ref": "x-mitre-detection-strategy--d1", "target_ref": "attack-pattern--3"},
    ]
    path = tmp_path / "enterprise-attack.json"
    path.write_text(json.dumps({"objects": objects}))
    return path


def rows(n_targets, conns, port, service, state, unique_ports=1, windows=3):
    out = []
    for w in range(windows):
        for t in range(n_targets):
            out.append(dict(window_start=window(w), src_ip_zeek="143.88.6.11", dest_ip_zeek=f"143.88.5.{t}",
                            connection_count=conns, total_duration=0.1 * conns, total_orig_bytes=50.0 * conns,
                            total_resp_bytes=40.0 * conns, unique_destination_ports=unique_ports,
                            most_common_destination_port=port, most_common_service=service,
                            most_common_connection_state=state, tcp_count=conns, udp_count=0, icmp_count=0))
    return pd.DataFrame(out)


# ---------------------------------------------------------------- behaviour check
def test_features_facts_and_reading_for_ssh_logins():
    f = incident_features(rows(2, 40, 22, "ssh", "SF"))
    assert f["connections"] == 240 and f["target_count"] == 2 and f["minutes"] == 15
    text = facts(f)
    assert text.startswith("internal host made 240 TCP connections to 2 internal hosts within 15 minutes")
    assert "(mostly 22); 0% failed or rejected, 100% completed normally" in text
    assert any("repeated login attempts against ssh" in r for r in interpret(f))


def test_reading_for_a_port_scan():
    reading = interpret(incident_features(rows(4, 300, 80, "http", "REJ", unique_ports=250)))
    assert reading[0].startswith("port scan") and any("rejected" in r for r in reading)
    assert not any("login" in r for r in reading)


def test_behavior_check_finds_a_technique_the_detector_did_not_name(stix):
    search = BehaviorSearch.load(stix)
    check = search.check(incident_features(rows(2, 40, 22, "ssh", "SF")), detector_technique="T1190")
    assert check["candidates"][0]["technique_id"] == "T1110"
    assert check["agrees_with_detector"] is False
    assert all(c["technique_id"] != "T1059" for c in check["candidates"])       # host-only technique dropped
    scan = search.check(incident_features(rows(4, 300, 80, "http", "REJ", unique_ports=250)), "T1595")
    assert scan["candidates"][0]["technique_id"] == "T1595" and scan["agrees_with_detector"] is True


def test_technique_docs_include_network_analytics(stix):
    docs = build_technique_docs(stix)
    assert set(docs) == {"T1110", "T1190", "T1595", "T1059"}
    assert "Many short connections" in docs["T1595"]["network_text"] and docs["T1110"]["network_text"] == ""
    assert TechniqueIndex(docs).rank("guessing passwords ssh login")[0][0] == "T1110"


# ---------------------------------------------------------------- knowledge files
def test_procedures_from_stix_and_lfs_pointers(stix, tmp_path):
    chunks = procedures_from_stix(stix)
    assert len(chunks) == 1 and chunks[0]["metadata"]["technique_ids"] == ["T1110"]
    assert chunks[0]["metadata"]["source_attack_id"] == "G9001" and "(Citation" not in chunks[0]["text"]
    pointer = tmp_path / "cti_chunks.jsonl"
    pointer.write_text("version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 10\n")
    assert is_lfs_pointer(pointer) and read_jsonl(pointer) == []


# ---------------------------------------------------------------- vector retrieval (notebook flow)
def fake_embed(texts):
    """Bag of hashed words: similar wording -> similar vectors. Enough to test the retrieval flow."""
    out = []
    for text in texts:
        v = np.zeros(64)
        for word in text.lower().split():
            v[int(hashlib.md5(word.strip(".,:;()").encode()).hexdigest(), 16) % 64] += 1
        out.append((v / (np.linalg.norm(v) or 1)).tolist())
    return out


def test_vector_retrieve_follows_the_notebook_fallbacks():
    chromadb = pytest.importorskip("chromadb")
    sources = {
        "cti": [{"id": "cti-1", "text": "The actor exploited the web server over http", "metadata":
                 {"technique_ids": ["T1190"], "apt_group": "APT1", "report": "R1"}},
                {"id": "cti-2", "text": "They scanned ports on many hosts", "metadata": {"technique_ids": ["T1595"]}}],
        "procedures": [{"id": "proc-1", "text": "Group exploited a public web application over http",
                        "metadata": {"technique_ids": ["T1190"], "source_name": "Op Web", "source_attack_id": "C0001"}}],
        "cve": [{"id": "CVE-2024-1", "text": "CVE-2024-1: HTTP server remote code execution", "metadata": {"cve_id": "CVE-2024-1"}},
                {"id": "CVE-2024-2", "text": "CVE-2024-2: printer driver bug", "metadata": {"cve_id": "CVE-2024-2"}}],
    }
    store = VectorStore.from_sources(chromadb.EphemeralClient(), fake_embed, "fake", sources)
    event = {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "service": "http",
             "protocol": "tcp", "port": 80, "behavior": "internal host made 30 TCP connections"}
    result = store.retrieve(event, siblings=["T1595"], k_cti=3)
    levels = [(e["source"], e["level"]) for e in result["evidence"]]
    assert levels[:3] == [("cti", "technique"), ("procedure", "procedure"), ("cti", "tactic")]
    assert result["fallback_to_tactic"] is True
    assert [e["ref"] for e in result["evidence"] if e["source"] == "cve"] == ["CVE-2024-1"]   # HTTP keyword filter
    cti = next(s for s in result["sources"] if s["source"] == "cti")
    assert cti == {"source": "cti", "searched": 2, "returned": 2}
    # non-exploit technique: no CVE search
    scan = store.retrieve({**event, "technique_id": "T1595", "technique_name": "Active Scanning"}, siblings=[])
    assert {"source": "cve", "returned": 0, "skipped": True} in scan["sources"]
    # the index is reused when nothing changed and rebuilt when a source changes
    client = store.client
    again = VectorStore.from_sources(client, fake_embed, "fake", sources)
    assert again.cols["cti"].count() == 2
    sources["cti"].append({"id": "cti-3", "text": "new chunk", "metadata": {"technique_ids": ["T1190"]}})
    assert VectorStore.from_sources(client, fake_embed, "fake", sources).cols["cti"].count() == 3


# ---------------------------------------------------------------- API
def test_incident_detail_includes_behavior_check(make_settings, stix):
    app = create_app(make_settings(attack_stix=stix))
    with TestClient(app, headers={"X-API-Key": API_KEY}) as c:
        c.post("/detect", json={"window_start": iso(2)})
        incident_id = c.get("/incidents").json()["incidents"][0]["incident_id"]
        detail = wait_ready(c, incident_id)
    check = detail["retrieval_trace"]["behavior_check"]
    # the fixture attacker sends rejected HTTP connections to 6 hosts; the detector says T1190
    assert check["facts"].startswith("internal host made 180 TCP connections to 6 internal hosts")
    assert check["method"] == "bm25" and check["candidates"]
    assert check["agrees_with_detector"] is (detail["technique_id"] in [c["technique_id"] for c in check["candidates"][:3]])


def test_disagreement_is_mentioned_in_the_fallback_explanation(make_settings, stix):
    app = create_app(make_settings(attack_stix=stix))
    state = app.state.app_state
    original = state.explanations.behavior.check

    def disagree(features, technique):
        result = original(features, technique)
        return {**result, "agrees_with_detector": False,
                "candidates": [{"technique_id": "T1110", "name": "Brute Force", "rank": 1}]}

    state.explanations.behavior.check = disagree
    with TestClient(app, headers={"X-API-Key": API_KEY}) as c:
        c.post("/detect", json={"window_start": iso(2)})
        incident_id = c.get("/incidents").json()["incidents"][0]["incident_id"]
        explanation = wait_ready(c, incident_id)["explanation"]
    assert any("T1110 (Brute Force)" in s["text"] for s in explanation["sentences"])


# ---------------------------------------------------------------- replay period (gapped test split)
def test_replay_reports_period_bounds_and_day_starts(make_settings, paths):
    edges = pd.read_parquet(paths / "test_edges.parquet")
    later = edges.copy()
    later["window_start"] = later["window_start"] + pd.Timedelta(days=20, hours=3)   # gap, next day starts at 19:00
    pd.concat([edges, later]).to_parquet(paths / "test_edges.parquet", index=False)
    with TestClient(create_app(make_settings()), headers={"X-API-Key": API_KEY}) as c:
        replay = c.get("/incidents").json()["replay"]
    assert replay["window_count"] == 24
    assert replay["first_window_start"] == iso(0)
    assert replay["last_window_start"] == (window(11) + pd.Timedelta(days=20, hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert replay["day_starts"] == [iso(0), (window(0) + pd.Timedelta(days=20, hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ")]


# ---------------------------------------------------------------- LLM reply parsing
def test_llm_reply_with_extra_text_and_braces_is_parsed():
    from app.explain import parse_llm_json
    reply = ('Here you go {not json}\n```json\n{"sentences": [{"text": "Scan from host-A {x}.", "citations": ["E1"]}], '
             '"next_steps": ["Block host-A"]}\n```\nHope this helps {}')
    parsed = parse_llm_json(reply, {"E1"})
    assert parsed["sentences"][0]["citations"] == ["E1"] and parsed["next_steps"] == ["Block host-A"]
    with pytest.raises(ValueError, match="max_tokens"):
        parse_llm_json('{"sentences": [{"text": "cut off', {"E1"})


def test_groq_request_uses_json_mode(make_settings, monkeypatch):
    from app import explain
    sent = []

    class Reply:
        status_code = 200
        def raise_for_status(self): pass
        def json(self): return {"choices": [{"message": {"content": '{"sentences": []}'}}]}

    monkeypatch.setattr(explain.requests, "post", lambda url, **kw: sent.append(kw["json"]) or Reply())
    settings = make_settings(llm_provider="groq", llm_model="openai/gpt-oss-20b", llm_base_url="https://x/v1")
    explain.LLMClient(settings).chat("hi")
    assert sent[0]["response_format"] == {"type": "json_object"} and sent[0]["reasoning_effort"] == "low"
    assert sent[0]["max_tokens"] == 2000


def test_no_distinctive_pattern_gives_no_candidates(stix):
    check = BehaviorSearch.load(stix).check(incident_features(rows(1, 2, 53, "dns", "SF", windows=1)), "T1046")
    assert check["reading"] == [] and check["candidates"] == [] and check["agrees_with_detector"] is None


def test_redactor_reveals_capitalised_aliases():
    from app.explain import Redactor
    r = Redactor(["143.88.4.11", "143.88.5.1"], enabled=True)
    assert r.reveal("Host-A scanned host-B. HOST-A again.") == "143.88.4.11 scanned 143.88.5.1. 143.88.4.11 again."
    assert r.hide("Traffic to 143.88.5.1. Not 143.88.5.10 or 143.88.4.110.") == "Traffic to host-B. Not 143.88.5.10 or 143.88.4.110."


# ---------------------------------------------------------------- window graph
def test_window_graph_around_the_incident_source(client):
    client.post("/detect", json={"window_start": iso(2)})
    incident_id = client.get("/incidents").json()["incidents"][0]["incident_id"]
    g = client.get(f"/incidents/{incident_id}/graph").json()
    assert g["window_start"] == iso(2) and g["windows"] == [iso(2)] and g["source_ip"] == "143.88.6.11"
    roles = {n["ip"]: n["role"] for n in g["nodes"]}
    assert roles["143.88.6.11"] == "source" and sum(r == "target" for r in roles.values()) == 6
    attack = [e for e in g["edges"] if e["source_ip"] == "143.88.6.11"]
    assert len(attack) == 6 and all(e["flagged"] and e["outcome"] == "refused" and e["in_two_hop"] for e in attack)
    assert all(not e["in_two_hop"] for e in g["edges"] if e["source_ip"] != "143.88.6.11")   # normal DNS traffic
    assert g["window_edge_count"] == 10 and not g["truncated"]
    assert client.get(f"/incidents/{incident_id}/graph", params={"window_start": iso(5)}).status_code == 400
    assert client.get("/incidents/INC-9999/graph").status_code == 404
