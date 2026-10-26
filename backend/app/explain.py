"""Incident explanations: retrieval runs inline, the LLM runs in the background.

Providers (LLM_PROVIDER):
- groq:  Groq's OpenAI-compatible API (the Oct 6 demo default, openai/gpt-oss-20b)
- local: any OpenAI-compatible server (vLLM, Ollama, LM Studio) - this is where the fine-tuned
         LLM (Model 4) plugs in, via LLM_BASE_URL and LLM_MODEL
- none:  evidence-only mode; sentences are synthesised from the evidence (mode = "fallback")
"""
from __future__ import annotations

import json
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import requests

from app.config import Settings
from app.incidents import Incident
from app.knowledge import KnowledgeBase
from app.timeutil import iso, now_iso

log = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are a SOC analyst. Using ONLY the incident and the numbered evidence provided, explain the "
    "incident for another analyst. Return JSON with keys 'sentences' (list of objects with 'text' and "
    "'citations', where citations are evidence IDs such as \"E1\" that support the sentence; use an empty "
    "list when no evidence supports it) and 'next_steps' (list of short imperative actions). Write 3 to 6 "
    "sentences. Do not invent actors, CVEs or facts that are not in the input."
)


class Redactor:
    """Replaces IPs with host-A, host-B, ... before text leaves the backend, and maps them back."""

    def __init__(self, ips: list[str], enabled: bool):
        self.enabled = enabled
        self.forward = {ip: f"host-{self._label(i)}" for i, ip in enumerate(dict.fromkeys(ips))} if enabled else {}
        self.backward = {alias: ip for ip, alias in self.forward.items()}

    @staticmethod
    def _label(i: int) -> str:
        label = ""
        i += 1
        while i:
            i, r = divmod(i - 1, 26)
            label = chr(65 + r) + label
        return label

    def _swap(self, text: str, mapping: dict[str, str]) -> str:
        for old in sorted(mapping, key=len, reverse=True):
            text = re.sub(rf"(?<![\w.]){re.escape(old)}(?![\w.])", mapping[old], text)
        return text

    def hide(self, text: str) -> str:
        return self._swap(text, self.forward) if self.enabled else text

    def reveal(self, text: str) -> str:
        return self._swap(text, self.backward) if self.enabled else text


def incident_brief(incident: Incident, kb: KnowledgeBase) -> dict:
    tactic, _ = incident.tactic(kb)
    targets = sorted({e.destination_ip for e in incident.edges})
    services = sorted({e.service for e in incident.edges if e.service})
    ports = sorted({e.port for e in incident.edges if e.port is not None})
    return {
        "source_ip": incident.source_ip,
        "technique_id": incident.effective_technique,
        "technique_name": kb.technique_name(incident.effective_technique),
        "tactic": tactic,
        "edge_count": incident.edge_count,
        "targets": targets[:20],
        "target_count": len(targets),
        "services": services,
        "ports": ports[:20],
        "max_attack_probability": round(max(e.attack_probability for e in incident.edges), 3),
        "first_seen": iso(incident.first_window),
        "last_seen": iso(incident.last_window),
    }


def retrieval_query(brief: dict) -> str:
    return " ".join(str(x) for x in [brief["technique_id"], brief["technique_name"], brief["tactic"],
                                      " ".join(brief["services"]), " ".join(map(str, brief["ports"][:5])),
                                      f"{brief['target_count']} targets", f"{brief['edge_count']} connections"])


def fallback_explanation(brief: dict, evidence: list[dict], mitigations: list[dict]) -> dict:
    sentences = [{
        "text": (f"{brief['source_ip']} contacted {brief['target_count']} host(s) over {brief['edge_count']} "
                 f"connection record(s) between {brief['first_seen']} and {brief['last_seen']}; the detector "
                 f"rates it up to {brief['max_attack_probability']:.0%} likely to be an attack."),
        "citations": [],
    }]
    mitre = next((e for e in evidence if e["source"] == "mitre"), None)
    if mitre:
        sentences.append({"text": (f"The behaviour matches MITRE ATT&CK {mitre['ref']} ({mitre['title']}) in the "
                                   f"{brief['tactic']} tactic: {mitre['text']}"), "citations": [mitre["evidence_id"]]})
    for item in [e for e in evidence if e["source"] != "mitre"][:2]:
        prefix = "Related tradecraft" if item["level"] == "tactic" else "Documented use"
        sentences.append({"text": f"{prefix}: {item['title']} - {item['text']}", "citations": [item["evidence_id"]]})
    steps = [f"Confirm whether {brief['source_ip']} is an authorised scanner or admin host; if not, isolate or rate-limit it.",
             f"Review logs for {brief['source_ip']} around {brief['first_seen']}-{brief['last_seen']}"
             + (f", focusing on {', '.join(brief['services'])}" if brief["services"] else "") + "."]
    steps += [f"Apply mitigation {m['mitigation_id']} ({m['name']})." for m in mitigations[:3]]
    return {"sentences": sentences, "next_steps": steps}


def parse_llm_json(text: str, valid_ids: set[str]) -> dict:
    match = re.search(r"\{.*\}", text or "", flags=re.S)
    if not match:
        raise ValueError("LLM reply contained no JSON object")
    payload = json.loads(match.group(0))
    sentences = []
    for item in payload.get("sentences", []):
        if isinstance(item, str):
            item = {"text": item, "citations": []}
        text_value = str(item.get("text", "")).strip()
        if text_value:
            sentences.append({"text": text_value,
                              "citations": [c for c in item.get("citations", []) if c in valid_ids]})
    if not sentences:
        raise ValueError("LLM reply had no sentences")
    return {"sentences": sentences, "next_steps": [str(s) for s in payload.get("next_steps", []) if str(s).strip()]}


class LLMClient:
    def __init__(self, settings: Settings):
        self.settings = settings

    @property
    def enabled(self) -> bool:
        s = self.settings
        return s.llm_provider in {"groq", "local"} and bool(s.llm_model) and bool(s.llm_base_url)

    def chat(self, user_prompt: str) -> str:
        s = self.settings
        headers = {"Content-Type": "application/json"}
        if s.llm_api_key:
            headers["Authorization"] = f"Bearer {s.llm_api_key}"
        response = requests.post(
            f"{s.llm_base_url.rstrip('/')}/chat/completions", headers=headers, timeout=s.llm_timeout_s,
            json={"model": s.llm_model, "temperature": 0.2, "max_tokens": 900,
                  "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                               {"role": "user", "content": user_prompt}]})
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]


class ExplanationManager:
    def __init__(self, settings: Settings, kb: KnowledgeBase, client: LLMClient | None = None, workers: int = 2):
        self.settings = settings
        self.kb = kb
        self.client = client or LLMClient(settings)
        self.pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="explain")
        self.lock = threading.Lock()
        self.running: set[str] = set()

    def view(self, incident: Incident, refresh: bool = False) -> dict:
        """Current explanation for the incident; starts a job on the first call or on refresh."""
        with self.lock:
            busy = incident.incident_id in self.running
            if incident.explanation is None or (refresh and not busy):
                self._start(incident)
            explanation = dict(incident.explanation)
        technique = explanation.pop("_technique", None)
        explanation["stale"] = (explanation.get("based_on_edge_count") != incident.edge_count
                                or technique != incident.effective_technique)
        return explanation

    def _start(self, incident: Incident) -> None:
        brief = incident_brief(incident, self.kb)
        retrieval = self.kb.retrieve(brief["technique_id"], brief["tactic"], retrieval_query(brief),
                                     self.settings.retrieval_top_k, self.settings.retrieval_min_score)
        incident.evidence = retrieval.evidence
        incident.retrieval_trace = retrieval.trace
        incident.cve_status = retrieval.cve_status
        incident.explanation = {"status": "generating", "started_at": now_iso(),
                                "based_on_edge_count": incident.edge_count, "_technique": brief["technique_id"],
                                "sentences": [], "next_steps": []}
        self.running.add(incident.incident_id)
        self.pool.submit(self._run, incident, brief, list(retrieval.evidence))

    def _run(self, incident: Incident, brief: dict, evidence: list[dict]) -> None:
        started = time.perf_counter()
        mitigations = self.kb.mitigations_for(brief["technique_id"])
        result, mode, model, message = None, "fallback", None, None
        try:
            if self.client.enabled:
                redactor = Redactor([brief["source_ip"], *brief["targets"]], self.settings.redact_ips)
                prompt = redactor.hide(json.dumps({
                    "incident": brief,
                    "evidence": [{k: e[k] for k in ("evidence_id", "source", "level", "ref", "title", "text")} for e in evidence],
                    "mitigations": mitigations[:5]}, ensure_ascii=False))
                try:
                    parsed = parse_llm_json(self.client.chat(prompt), {e["evidence_id"] for e in evidence})
                    result = {"sentences": [{"text": redactor.reveal(s["text"]), "citations": s["citations"]}
                                            for s in parsed["sentences"]],
                              "next_steps": [redactor.reveal(s) for s in parsed["next_steps"]]}
                    mode, model = "llm", self.settings.llm_model
                except Exception as exc:  # noqa: BLE001 - keep the demo usable without the LLM
                    log.warning("LLM explanation failed for %s: %s", incident.incident_id, exc)
                    message = f"LLM unavailable, used evidence-only fallback ({type(exc).__name__})"
            if result is None:
                result = fallback_explanation(brief, evidence, mitigations)
            sentences = result["sentences"]
            grounded = sum(1 for s in sentences if s["citations"]) / len(sentences) if sentences else 0.0
            update = {"status": "ready", "mode": mode, "model": model, "message": message,
                      "latency_ms": int((time.perf_counter() - started) * 1000),
                      "groundedness": round(grounded, 3), **result}
        except Exception as exc:  # noqa: BLE001
            log.exception("Explanation failed for %s", incident.incident_id)
            update = {"status": "error", "message": str(exc)}
        with self.lock:
            incident.explanation = {**incident.explanation, **update}
            incident.explanation.pop("started_at", None)
            self.running.discard(incident.incident_id)

    def wait_idle(self, timeout: float = 10.0) -> None:
        """Test helper: block until no explanation job is running."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self.lock:
                if not self.running:
                    return
            time.sleep(0.02)
