"""RAG vs no-RAG ablation for the LLM explanations.

Run from the backend folder, with the same .env the backend uses:
    python scripts/eval_rag_ablation.py --n 100

For the same sample of incidents it asks the LLM twice:
    rag     the app's prompt: incident record + retrieved evidence (+ behaviour check)
    no_rag  the incident record only; the LLM may use its own knowledge
and measures, per answer:
    true_technique_named   the explanation names a ground-truth technique (ID or name)
    unsupported_ids        technique / CVE IDs that appear neither in the input nor in the evidence
    unsupported_groups     ATT&CK threat groups named that are not in the input or evidence
    groundedness           share of sentences citing evidence (rag only)
Outputs eval_rag_ablation.csv (one row per incident and arm) and eval_rag_ablation_summary.json.
--dry-run checks the pipeline without calling the LLM.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "scripts"))

NO_RAG_PROMPT = (
    "You are a SOC analyst writing for another analyst. Use the incident record and your own knowledge of MITRE "
    "ATT&CK. Return JSON with keys 'sentences' (list of {'text', 'citations'}) and 'next_steps' (2 to 4 short "
    "imperative actions). Write 3 to 5 sentences in this order: (1) what the source host did, from the incident "
    "record (target_count hosts, ports, time span); (2) why this matches the technique; (3) one or two sentences on "
    "similar documented activity. There is no evidence list, so every 'citations' is []. Report the number of "
    "target hosts, not IP ranges or address lists. detector_attack_probability is the detector's confidence that "
    "the traffic is an attack."
)
ID_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?|CVE-\d{4}-\d{4,7})\b", re.I)


def chat(settings, system: str, user: str) -> str:
    import requests
    from app import explain
    if system == explain.SYSTEM_PROMPT:
        return explain.LLMClient(settings).chat(user)
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {settings.llm_api_key}"}
    body = {"model": settings.llm_model, "temperature": 0.2, "max_tokens": settings.llm_max_tokens,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
    if settings.llm_provider == "groq":
        body["response_format"] = {"type": "json_object"}
        if settings.llm_model.startswith("openai/gpt-oss"):
            body["reasoning_effort"] = "low"
    r = requests.post(f"{settings.llm_base_url.rstrip('/')}/chat/completions", headers=headers,
                      timeout=settings.llm_timeout_s, json=body)
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"] or ""


def with_retry(fn, tries: int = 5):
    for i in range(tries):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - rate limits (429) and timeouts: wait and retry
            if i == tries - 1:
                raise
            wait = 10 * (i + 1)
            print(f"   retry in {wait}s ({type(exc).__name__}: {str(exc)[:80]})", flush=True)
            time.sleep(wait)


def group_names(stix_path) -> dict[str, str]:
    """lower-case name/alias -> group name, from the ATT&CK bundle"""
    out = {}
    if stix_path and Path(stix_path).exists():
        for o in json.loads(Path(stix_path).read_text(encoding="utf-8")).get("objects", []):
            if o.get("type") == "intrusion-set" and not o.get("revoked"):
                for n in [o["name"], *o.get("aliases", [])]:
                    if len(n) >= 4:
                        out[n.lower()] = o["name"]
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, default=100)
    parser.add_argument("--pause", type=float, default=2.0, help="seconds between LLM calls (Groq rate limits)")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    from eval_explanations import load_env
    load_env(HERE / ".env")

    import numpy as np
    import pandas as pd
    from fastapi.testclient import TestClient
    from app.behavior import event_fields
    from app.explain import SYSTEM_PROMPT, incident_brief, parse_llm_json, retrieval_query
    from app.main import create_app

    app = create_app()
    st = app.state.app_state
    settings, kb, ex, data = st.settings, st.kb, st.explanations, st.replay_data
    if not args.dry_run and not ex.client.enabled:
        sys.exit("No LLM configured in backend/.env (GROQ_API_KEY or LLM_*). Use --dry-run to test the pipeline.")
    c = TestClient(app, headers={"X-API-Key": settings.api_key})
    print("Replaying the test split...", flush=True)
    c.post("/detect", json={"reset": True})
    while c.post("/detect", json={}).status_code == 200:
        pass

    def truth_of(inc):
        t = set()
        for e in inc.edges:
            v = data.frame.loc[e.row, "mitre_targets"] if "mitre_targets" in data.frame else None
            if v is not None and not (isinstance(v, float) and np.isnan(v)):
                t |= {str(x).split(".")[0] for x in v}
        return t

    incidents = [i for i in st.controller.state.incidents.values() if truth_of(i)]
    frame = pd.DataFrame({"inc": incidents, "technique": [i.technique_id for i in incidents]})
    share = frame.technique.value_counts(normalize=True)
    picks = [frame[frame.technique == t].sample(min((frame.technique == t).sum(), max(2, round(f * args.n))), random_state=42)
             for t, f in share.items()]
    sample = pd.concat(picks).head(args.n)
    groups = group_names(settings.attack_stix)
    print(f"{len(incidents)} labelled incidents, sampling {len(sample)}; LLM: {settings.llm_model}", flush=True)

    rows = []
    for n, inc in enumerate(sample.inc, 1):
        truth = truth_of(inc)
        brief = incident_brief(inc, kb)
        f = ex._features(inc)
        r = kb.retrieve(brief["technique_id"], brief["tactic"], retrieval_query(brief), settings.retrieval_top_k,
                        settings.retrieval_min_score, event=event_fields(f) if f is not None else None)
        evidence = r.evidence
        check = ex.behavior.check(f, brief["technique_id"]) if f is not None and ex.behavior and ex.behavior.enabled else None
        rag_brief = dict(brief)
        if check and check["agrees_with_detector"] is False:
            rag_brief["behavior_check"] = {k: check[k] for k in ("reading", "candidates", "agrees_with_detector")}
        rag_input = json.dumps({"incident": rag_brief, "evidence": [{k: e[k] for k in ("evidence_id", "source", "level", "ref", "title", "text")} for e in evidence],
                                "mitigations": kb.mitigations_for(brief["technique_id"])[:5]}, ensure_ascii=False)
        plain_input = json.dumps({"incident": brief}, ensure_ascii=False)
        truth_names = {t: (kb.technique_name(t) or "").lower() for t in truth}
        for arm, system, user in (("rag", SYSTEM_PROMPT, rag_input), ("no_rag", NO_RAG_PROMPT, plain_input)):
            started = time.time()
            try:
                if args.dry_run:
                    reply = json.dumps({"sentences": [{"text": f"Matches {brief['technique_id']} {brief['technique_name']}.",
                                                       "citations": [evidence[0]["evidence_id"]] if arm == "rag" and evidence else []}],
                                        "next_steps": ["Check the host."]})
                else:
                    reply = with_retry(lambda: chat(settings, system, user))
                parsed = parse_llm_json(reply, {e["evidence_id"] for e in evidence} if arm == "rag" else set())
                error = None
            except Exception as exc:  # noqa: BLE001
                parsed, error = {"sentences": [], "next_steps": []}, f"{type(exc).__name__}: {exc}"
            text = " ".join(s["text"] for s in parsed["sentences"])
            low = text.lower()
            allowed = (user if arm == "rag" else plain_input).lower()
            ids = {m.upper() for m in ID_RE.findall(text)}
            unsupported_ids = sorted(i for i in ids if i.lower() not in allowed)
            named = {g for alias, g in groups.items() if re.search(rf"(?<!\w){re.escape(alias)}(?!\w)", low)}
            unsupported_groups = sorted(g for g in named if g.lower() not in allowed)
            sents = parsed["sentences"]
            rows.append({
                "incident_id": inc.incident_id, "arm": arm, "detector_technique": brief["technique_id"],
                "truth": ",".join(sorted(truth)), "detector_correct": brief["technique_id"].split(".")[0] in truth,
                "error": error, "sentences": len(sents),
                "groundedness": (sum(bool(s["citations"]) for s in sents) / len(sents)) if sents and arm == "rag" else None,
                "true_technique_named": any(t.lower() in low or (nm and nm in low) for t, nm in truth_names.items()),
                "unsupported_ids": ",".join(unsupported_ids), "unsupported_groups": ",".join(unsupported_groups),
                "latency_s": round(time.time() - started, 2), "text": text,
            })
            if not args.dry_run:
                time.sleep(args.pause)
        print(f"{n}/{len(sample)} {inc.incident_id} done", flush=True)

    out = pd.DataFrame(rows)
    out.to_csv("eval_rag_ablation.csv", index=False)
    ok = out[out.error.isna() & (out.sentences > 0)]
    summary = {"incidents": len(sample), "llm": settings.llm_model, "arms": {}}
    for arm, g in ok.groupby("arm"):
        summary["arms"][arm] = {
            "answers": len(g),
            "true_technique_named": round(float(g.true_technique_named.mean()), 4),
            "true_technique_named_when_detector_wrong": round(float(g[~g.detector_correct].true_technique_named.mean()), 4) if (~g.detector_correct).any() else None,
            "answers_with_unsupported_ids": round(float((g.unsupported_ids.fillna("") != "").mean()), 4),
            "answers_with_unsupported_groups": round(float((g.unsupported_groups.fillna("") != "").mean()), 4),
            "groundedness_mean": round(float(g.groundedness.mean()), 4) if g.groundedness.notna().any() else None,
            "sentences_mean": round(float(g.sentences.mean()), 2),
            "latency_s_mean": round(float(g.latency_s.mean()), 2),
        }
    summary["failed_answers"] = int(len(out) - len(ok))
    Path("eval_rag_ablation_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
