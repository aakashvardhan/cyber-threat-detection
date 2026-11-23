"""Incident chat: follow-up questions about one incident, answered from fresh GraphRAG retrieval with citations.

For each question:
  1. Rewrite   the LLM turns the question and the recent conversation into a standalone search query, and names a
               technique if the analyst asks about a different one ("could this be brute force instead?")
  2. Retrieve  GraphRAG from the incident's technique (plus the named technique as an alternative), with the
               rewritten query, so the reranker orders the text evidence by the question, not by the incident alone
  3. Answer    the LLM answers only from the incident record, the earlier explanation, the conversation and the
               numbered evidence, citing evidence IDs; citations to unknown IDs are dropped
  4. Remember  the turn is kept on the incident (last MAX_MESSAGES messages) and saved to the incident store
               (DynamoDB), so the conversation survives a restart

Without an LLM (LLM_PROVIDER=none) or when it fails, the answer lists the evidence most related to the question.
IPs are replaced with host-A, host-B, ... in everything sent to the LLM, as for explanations.
"""
from __future__ import annotations

import json
import logging
import re
import time

from app.explain import Redactor, incident_brief, parse_llm_json
from app.incidents import Incident
from app.store import chat_state
from app.timeutil import now_iso

log = logging.getLogger(__name__)

MAX_MESSAGES = 20          # kept per incident (10 questions and answers)
CONTEXT_TURNS = 6          # earlier messages sent to the LLM
MAX_QUESTION = 1000

REWRITE_PROMPT = (
    "You prepare a search query for a security knowledge base (MITRE ATT&CK techniques, threat groups, procedure "
    "examples, threat-intelligence reports, CVEs). Given an incident summary, the recent conversation and the "
    "analyst's new question, return JSON with keys 'query' (a standalone search query of at most 25 words that "
    "resolves references such as 'it' or 'that group' from the conversation) and 'technique_id' (an ATT&CK "
    "technique ID such as \"T1110\" only if the question asks about a technique other than the incident's, "
    "otherwise null)."
)

CHAT_PROMPT = (
    "You are a SOC analyst answering a colleague's follow-up question about one incident. Use ONLY the incident "
    "record, the earlier explanation, the conversation and the numbered evidence. Return JSON with key 'sentences' "
    "(a list of {'text', 'citations'}), 1 to 5 sentences that answer the question directly. Citations are evidence "
    "IDs such as \"E2\"; cite an ID only when its text supports the sentence, and never write evidence IDs in the "
    "text. Evidence about threat groups describes documented users of a technique: never say a group carried out "
    "this incident. If the evidence does not answer the question, say so plainly and suggest what to check instead. "
    "Do not invent actors, CVEs, numbers or facts that are not in the input."
)


def _json_object(text: str) -> dict:
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", text or ""):
        try:
            obj, _ = decoder.raw_decode(text, match.start())
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return obj
    raise ValueError("no JSON object in the reply")


class IncidentChat:
    def __init__(self, explanations, store=None, model_name=lambda: None):
        self.x = explanations                 # ExplanationManager: settings, knowledge base, GraphRAG, LLM client
        self.store = store
        self.model_name = model_name

    @property
    def llm_enabled(self) -> bool:
        return self.x.client.enabled

    def _known(self, technique_id: str) -> bool:
        graph = getattr(self.x.graph, "graph", None)
        return bool(self.x.kb.technique(technique_id)) or (graph is not None and
                                                           technique_id.split(".")[0] in graph.nodes)

    # ------------------------------------------------------------------ steps
    def _rewrite(self, brief: dict, turns: list[dict], question: str, redactor: Redactor) -> tuple[str, str | None]:
        fallback = f"{brief['technique_name']} {question}"
        if not self.llm_enabled:
            return fallback, None
        prompt = redactor.hide(json.dumps({
            "incident": {k: brief[k] for k in ("technique_id", "technique_name", "tactic", "services", "ports",
                                               "target_count")},
            "conversation": [{"role": t["role"], "text": t["text"]} for t in turns],
            "question": question}, ensure_ascii=False))
        try:
            reply = _json_object(self.x.client.chat(prompt, REWRITE_PROMPT))
            query = redactor.reveal(str(reply.get("query") or "").strip()) or fallback
            technique = str(reply.get("technique_id") or "").strip().upper() or None
            if technique and not self._known(technique):
                technique = None
            return query[:300], technique
        except Exception as exc:  # noqa: BLE001 - the question itself is still a usable query
            log.warning("Query rewrite failed: %s: %s", type(exc).__name__, exc)
            return fallback, None

    def _retrieve(self, incident: Incident, brief: dict, query: str, other: str | None):
        x = self.x
        features = x._features(incident)
        from app.behavior import event_fields
        event = event_fields(features) if features is not None else None
        if x.graph is not None:
            alternatives = [other] if other and other.split(".")[0] != brief["technique_id"].split(".")[0] else []
            return x.graph.retrieve(brief["technique_id"], brief["tactic"], query, x.settings.retrieval_top_k,
                                    event=event, alternatives=alternatives, history=x._history(incident))
        retrieval = x.kb.retrieve(other or brief["technique_id"], brief["tactic"], query, x.settings.retrieval_top_k,
                                  x.settings.retrieval_min_score, event=event)
        retrieval.trace.setdefault("retriever", "vector" if x.kb.vector is not None else "token")
        return retrieval

    def _answer(self, brief, incident, turns, question, evidence, redactor) -> tuple[list[dict], str, str | None, str | None]:
        if self.llm_enabled:
            earlier = (incident.explanation or {}).get("sentences") or []
            prompt = redactor.hide(json.dumps({
                "incident": brief,
                "earlier_explanation": [s["text"] for s in earlier],
                "conversation": [{"role": t["role"], "text": t["text"]} for t in turns],
                "question": question,
                "evidence": [{k: e[k] for k in ("evidence_id", "source", "level", "ref", "title", "text")}
                             for e in evidence]}, ensure_ascii=False))
            try:
                parsed = parse_llm_json(self.x.client.chat(prompt, CHAT_PROMPT), {e["evidence_id"] for e in evidence})
                sentences = [{"text": redactor.reveal(s["text"]), "citations": s["citations"]} for s in parsed["sentences"]]
                return sentences, "llm", self.x.settings.llm_model, None
            except Exception as exc:  # noqa: BLE001
                log.warning("Chat answer failed for %s: %s: %s", incident.incident_id, type(exc).__name__, exc)
                message = f"LLM unavailable, showing the most related evidence ({type(exc).__name__})"
        else:
            message = "LLM is off (LLM_PROVIDER=none); showing the most related evidence"
        related = [e for e in evidence if e["source"] not in ("mitre",)][:3] or evidence[:1]
        sentences = [{"text": "The most related evidence for this question:", "citations": []}]
        sentences += [{"text": f"{e['title']}: {e['text']}", "citations": [e["evidence_id"]]} for e in related]
        return sentences, "evidence", None, message

    # ------------------------------------------------------------------ public
    def ask(self, incident: Incident, question: str) -> dict:
        started = time.perf_counter()
        question = question.strip()[:MAX_QUESTION]
        brief = incident_brief(incident, self.x.kb)
        turns = list(incident.chat)[-CONTEXT_TURNS:]
        redactor = Redactor([brief["source_ip"], *brief["targets"]], self.x.settings.redact_ips)
        query, other = self._rewrite(brief, turns, question, redactor)
        retrieval = self._retrieve(incident, brief, query, other)
        evidence = list(retrieval.evidence)
        sentences, mode, model, message = self._answer(brief, incident, turns, question, evidence, redactor)
        cited = {c for s in sentences for c in s["citations"]}
        user = {"role": "user", "text": question, "at": now_iso()}
        answer = {"role": "assistant", "text": " ".join(s["text"] for s in sentences), "at": now_iso(),
                  "sentences": sentences, "evidence": [e for e in evidence if e["evidence_id"] in cited] or evidence[:3],
                  "query": query, "technique_asked": other, "mode": mode, "model": model, "message": message,
                  "retriever": retrieval.trace.get("retriever"), "rerank": retrieval.trace.get("rerank"),
                  "latency_ms": int((time.perf_counter() - started) * 1000)}
        incident.chat = [*incident.chat, user, answer][-MAX_MESSAGES:]
        self.save(incident)
        return answer

    def clear(self, incident: Incident) -> None:
        incident.chat = []
        self.save(incident)

    def save(self, incident: Incident) -> None:
        if self.store is not None and self.model_name():
            self.store.save(self.model_name(), incident.incident_id, chat_state(incident))
