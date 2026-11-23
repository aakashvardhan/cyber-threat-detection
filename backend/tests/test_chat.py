"""Incident chat (POST /incidents/{id}/chat): query rewrite, fresh retrieval, cited answers, memory."""
import json

from fastapi.testclient import TestClient

from app.chat import CHAT_PROMPT, REWRITE_PROMPT
from app.main import create_app
from conftest import API_KEY, ATTACKER, wait_ready, window


def iso(i):
    return window(i).strftime("%Y-%m-%dT%H:%M:%SZ")


class ScriptedLLM:
    """Answers the rewrite prompt and the chat prompt; records what was sent."""

    enabled = True

    def __init__(self, rewrite=None, answer=None):
        self.rewrite = rewrite or {"query": "active scanning of address ranges", "technique_id": "T1595"}
        self.answer = answer
        self.calls = []

    def chat(self, user_prompt, system_prompt=None):
        self.calls.append((system_prompt, user_prompt))
        if system_prompt == REWRITE_PROMPT:
            return json.dumps(self.rewrite)
        if system_prompt == CHAT_PROMPT:
            return json.dumps(self.answer or {"sentences": [
                {"text": "host-A matches the technique description.", "citations": ["E1", "E42"]},
                {"text": "Check authentication logs next.", "citations": []}]})
        return json.dumps({"sentences": [{"text": "Explained.", "citations": []}], "next_steps": []})


def first_incident(c):
    c.post("/detect", json={"window_start": iso(2)})
    incident_id = c.get("/incidents").json()["incidents"][0]["incident_id"]
    wait_ready(c, incident_id)
    return incident_id


def test_chat_without_llm_returns_related_evidence(client):
    incident_id = first_incident(client)
    assert client.get(f"/incidents/{incident_id}/chat").json() == {"incident_id": incident_id, "llm_enabled": False,
                                                                   "messages": []}
    thread = client.post(f"/incidents/{incident_id}/chat", json={"message": "Which groups use this?"}).json()
    user, answer = thread["messages"]
    assert user == {"role": "user", "text": "Which groups use this?", "at": user["at"]}
    assert answer["role"] == "assistant" and answer["mode"] == "evidence" and "LLM is off" in answer["message"]
    assert answer["evidence"] and all(s["citations"] for s in answer["sentences"][1:])
    assert answer["query"].endswith("Which groups use this?")


def test_chat_with_llm_rewrites_retrieves_cites_and_redacts(make_settings):
    settings = make_settings(llm_provider="local", llm_model="m", redact_ips=True)
    app = create_app(settings)
    llm = ScriptedLLM()
    app.state.app_state.explanations.client = llm
    with TestClient(app, headers={"X-API-Key": API_KEY}) as c:
        incident_id = first_incident(c)
        c.post(f"/incidents/{incident_id}/chat", json={"message": f"Is {ATTACKER} doing something else?"})
        thread = c.post(f"/incidents/{incident_id}/chat", json={"message": "Could it be scanning instead?"}).json()
    answer = thread["messages"][-1]
    assert answer["mode"] == "llm" and answer["model"] == "m"
    assert answer["query"] == "active scanning of address ranges" and answer["technique_asked"] == "T1595"
    assert answer["sentences"][0]["text"].startswith(ATTACKER)                   # alias mapped back
    assert answer["sentences"][0]["citations"] == ["E1"]                         # E42 does not exist
    assert [e["evidence_id"] for e in answer["evidence"]] == ["E1"]
    sent = [u for s, u in llm.calls if s in (REWRITE_PROMPT, CHAT_PROMPT)]
    assert sent and all(ATTACKER not in u for u in sent)                         # no IP reaches the LLM
    last_chat = json.loads(next(u for s, u in reversed(llm.calls) if s == CHAT_PROMPT))
    assert [t["role"] for t in last_chat["conversation"]] == ["user", "assistant"]   # memory of the first turn
    assert len(thread["messages"]) == 4


def test_unknown_technique_from_the_rewrite_is_ignored(make_settings):
    settings = make_settings(llm_provider="local", llm_model="m")
    app = create_app(settings)
    app.state.app_state.explanations.client = ScriptedLLM(rewrite={"query": "x", "technique_id": "T9999"})
    with TestClient(app, headers={"X-API-Key": API_KEY}) as c:
        incident_id = first_incident(c)
        answer = c.post(f"/incidents/{incident_id}/chat", json={"message": "and T9999?"}).json()["messages"][-1]
    assert answer.get("technique_asked") is None


def test_chat_survives_reset_and_can_be_cleared(client):
    incident_id = first_incident(client)
    client.post(f"/incidents/{incident_id}/chat", json={"message": "What next?"})
    client.post("/detect", json={"reset": True})
    client.post("/detect", json={"window_start": iso(2)})
    assert len(client.get(f"/incidents/{incident_id}/chat").json()["messages"]) == 2
    assert client.delete(f"/incidents/{incident_id}/chat").json()["messages"] == []
    assert client.get(f"/incidents/{incident_id}/chat").json()["messages"] == []


def test_chat_validates_input(client):
    incident_id = first_incident(client)
    assert client.post(f"/incidents/{incident_id}/chat", json={"message": ""}).status_code == 422
    assert client.post("/incidents/INC-9999/chat", json={"message": "hi"}).status_code == 404


def test_chat_uses_graphrag_with_the_asked_technique_as_alternative(make_settings, tmp_path):
    from test_graph_rag import make_stix
    settings = make_settings(attack_stix=make_stix(tmp_path / "stix.json"), retriever="graph",
                             llm_provider="local", llm_model="m")
    app = create_app(settings)
    llm = ScriptedLLM(rewrite={"query": "brute force passwords", "technique_id": "T1110"})
    app.state.app_state.explanations.client = llm
    with TestClient(app, headers={"X-API-Key": API_KEY}) as c:
        incident_id = first_incident(c)
        answer = c.post(f"/incidents/{incident_id}/chat", json={"message": "Or brute force?"}).json()["messages"][-1]
    assert answer["retriever"] == "graph" and answer["technique_asked"] == "T1110"
    evidence = json.loads(next(u for s, u in reversed(llm.calls) if s == CHAT_PROMPT))["evidence"]
    assert any(e["title"].startswith("Alternative: T1110") for e in evidence)


def test_browser_may_clear_the_chat(client):
    r = client.options("/incidents/INC-0001/chat", headers={"Origin": "http://localhost:5173",
                                                             "Access-Control-Request-Method": "DELETE"})
    assert r.status_code == 200 and "DELETE" in r.headers["access-control-allow-methods"]
