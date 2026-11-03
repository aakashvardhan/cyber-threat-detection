"""RAG evaluation with an LLM judge: retriever and generator metrics from the course material.

Run from the backend folder, with the same .env the backend uses:
    python scripts/eval_rag_judge.py --n 50

For N labelled test incidents it lets the app build each explanation exactly as the console does
(retrieval + behaviour check + LLM), then asks a judge LLM, in one call per incident, for the verdicts behind:

  Retriever  Contextual Precision  relevant evidence (for the true technique) ranked above irrelevant evidence
             Contextual Recall     share of the expected-answer statements that the evidence supports
             Contextual Relevancy  share of retrieved evidence that is relevant to the incident
  Generator  Faithfulness          share of explanation claims supported by the retrieved evidence
             Answer Relevancy      share of explanation statements that address the incident

The expected answer is the MITRE ATT&CK definition of the incident's ground-truth technique.
Outputs: eval_rag_judge.csv (one row per incident) and eval_rag_judge_summary.json.
--judge-model picks another Groq model as the judge (default: the backend's LLM_MODEL).
--dry-run checks the pipeline without calling any LLM.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "scripts"))

JUDGE_PROMPT = """You are evaluating a retrieval-augmented explanation of a network-security incident.
Judge only from the texts given. Return one JSON object with exactly these keys:

"evidence": a list with one object per evidence item, in the given order:
   {"id": "<evidence id>",
    "relevant_to_incident": "yes" or "no",     // is this item about the kind of activity in the INCIDENT?
    "useful_for_expected": "yes" or "no"}     // would it help to state the EXPECTED ANSWER?
"expected_statements": a list of the 2-5 key statements of the EXPECTED ANSWER, each
   {"statement": "...", "supported_by_evidence": "yes" or "no"}   // can it be attributed to any evidence item?
"claims": every factual claim made in the EXPLANATION, each
   {"claim": "...", "supported": "yes", "no" or "idk"}   // yes = stated or directly implied by the INCIDENT or the EVIDENCE;
                                                         // no = contradicted; idk = not in the input
"statements": every sentence of the EXPLANATION, each
   {"statement": "...", "relevant": "yes" or "no"}    // does it help explain THIS incident?
"""


def retry(fn, tries: int = 8):
    """Retry rate limits (429, honouring Retry-After) and transient errors."""
    for i in range(tries):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            if i == tries - 1:
                raise
            response = getattr(exc, "response", None)
            wait = min(60, 15 * (i + 1))
            if response is not None and response.status_code == 429:
                try:
                    wait = max(2.0, float(response.headers.get("retry-after", wait))) + 1
                except ValueError:
                    pass
            print(f"   waiting {wait:.0f}s ({type(exc).__name__}: {str(exc)[:70]})", flush=True)
            time.sleep(wait)


def judge_call(settings, model: str, user: str) -> dict:
    import requests
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {settings.llm_api_key}"}
    body = {"model": model, "temperature": 0, "max_tokens": 2500,
            "messages": [{"role": "system", "content": JUDGE_PROMPT}, {"role": "user", "content": user}],
            "response_format": {"type": "json_object"}}
    if model.startswith("openai/gpt-oss"):
        body["reasoning_effort"] = "low"

    def call():
        r = requests.post(f"{settings.llm_base_url.rstrip('/')}/chat/completions", headers=headers, json=body,
                          timeout=max(settings.llm_timeout_s, 90))
        r.raise_for_status()
        text = r.json()["choices"][0]["message"]["content"] or ""
        return json.loads(text[text.find("{"): text.rfind("}") + 1])
    return retry(call)


def yes(v) -> bool:
    return str(v).strip().lower().startswith("y")


def scores(verdict: dict) -> dict:
    ev = verdict.get("evidence") or []
    useful = [yes(e.get("useful_for_expected")) for e in ev]
    # DeepEval-style contextual precision: mean precision@k over the ranks k that hold a useful item
    hits, prec = 0, []
    for k, u in enumerate(useful, 1):
        if u:
            hits += 1
            prec.append(hits / k)
    exp = verdict.get("expected_statements") or []
    claims = verdict.get("claims") or []
    stm = verdict.get("statements") or []
    mean = lambda xs: (sum(xs) / len(xs)) if xs else None
    return {
        "contextual_precision": (sum(prec) / hits) if hits else (0.0 if ev else None),
        "contextual_recall": mean([yes(s.get("supported_by_evidence")) for s in exp]),
        "contextual_relevancy": mean([yes(e.get("relevant_to_incident")) for e in ev]),
        "faithfulness": mean([yes(c.get("supported")) for c in claims]),
        "answer_relevancy": mean([yes(s.get("relevant")) for s in stm]),
        "claims": len(claims), "unsupported_claims": sum(str(c.get("supported", "")).lower() in ("no", "idk") for c in claims),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, default=50)
    parser.add_argument("--judge-model", default=None,
                        help="judge LLM; default openai/gpt-oss-120b on Groq (a different model has its own rate limits)")
    parser.add_argument("--workers", type=int, default=1, help="parallel judge calls")
    parser.add_argument("--timeout", type=float, default=120, help="seconds to wait for one explanation")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    from eval_explanations import load_env
    load_env(HERE / ".env")

    import numpy as np
    import pandas as pd
    from fastapi.testclient import TestClient
    from app.main import create_app

    app = create_app()
    st = app.state.app_state
    settings, kb, data = st.settings, st.kb, st.replay_data
    if not args.dry_run and not st.explanations.client.enabled:
        sys.exit("No LLM configured in backend/.env (GROQ_API_KEY or LLM_*). Use --dry-run to test the pipeline.")
    judge_model = args.judge_model or ("openai/gpt-oss-120b" if settings.llm_provider == "groq" else settings.llm_model)
    c = TestClient(app, headers={"X-API-Key": settings.api_key})
    print("Running detection over the test split...", flush=True)
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
    sample = pd.concat([frame[frame.technique == t].sample(min((frame.technique == t).sum(), max(2, round(f * args.n))),
                                                           random_state=42) for t, f in share.items()]).head(args.n)
    print(f"{len(incidents)} labelled incidents, sampling {len(sample)}; judge: {judge_model}", flush=True)

    # 1) explanations, exactly as the console builds them, one incident at a time (Groq rate limits);
    #    the app's LLM call is wrapped with retries so a 429 does not fall back to the template
    if args.dry_run:
        st.explanations.client.chat = lambda prompt: json.dumps(
            {"sentences": [{"text": "The source scanned many hosts.", "citations": []},
                           {"text": "This matches the technique.", "citations": ["E1"]}], "next_steps": ["Check it."]})
        st.explanations.client.__class__.enabled = property(lambda self: True)
    else:
        original_chat = st.explanations.client.chat
        st.explanations.client.chat = lambda prompt: retry(lambda: original_chat(prompt))
    details = {}

    def explain(inc):
        d = c.get(f"/incidents/{inc.incident_id}").json()
        if d["explanation"].get("status") == "ready" and d["explanation"].get("mode") != "llm":
            d = c.get(f"/incidents/{inc.incident_id}?refresh_explanation=true").json()   # earlier template fallback
        deadline = time.time() + args.timeout * 4
        while d["explanation"]["status"] == "generating" and time.time() < deadline:
            time.sleep(2)
            d = c.get(f"/incidents/{inc.incident_id}").json()
        details[inc.incident_id] = d
        return d["explanation"].get("mode")

    # 2) one judge call per incident
    def judge(inc):
        d = details.get(inc.incident_id)
        if d is None or d["explanation"].get("status") != "ready":
            return {"incident_id": inc.incident_id, "error": "explanation not ready"}
        truth = sorted(truth_of(inc))
        expected = " ".join(f"{t} {kb.technique_name(t)}: {re.sub(r'[(]Citation:[^)]*[)]', '', str((kb.technique(t) or {}).get('description', '')))[:450]}"
                            for t in truth)
        evidence = [{"id": e["evidence_id"], "source": e["source"], "title": e["title"], "text": e["text"][:350]} for e in d["evidence"]]
        explanation = " ".join(s["text"] for s in d["explanation"]["sentences"])
        # the same incident record the explanation LLM saw (incl. attack probability, ports, behaviour check)
        from app.behavior import event_fields
        from app.explain import incident_brief
        brief = incident_brief(inc, kb)
        trace_check = (d.get("retrieval_trace") or {}).get("behavior_check")
        if trace_check and trace_check.get("agrees_with_detector") is False:
            brief["behavior_check"] = {k: trace_check.get(k) for k in ("reading", "candidates", "agrees_with_detector")}
        user = json.dumps({"INCIDENT": brief, "EVIDENCE": evidence, "EXPLANATION": explanation, "EXPECTED ANSWER": expected},
                          ensure_ascii=False)
        row = {"incident_id": inc.incident_id, "detector_technique": inc.technique_id, "truth": ",".join(truth),
               "detector_correct": inc.technique_id.split(".")[0] in truth, "mode": d["explanation"].get("mode"),
               "groundedness": d["explanation"].get("groundedness"), "evidence_items": len(evidence)}
        try:
            if args.dry_run:
                verdict = {"evidence": [{"id": e["id"], "relevant_to_incident": "yes", "useful_for_expected": "yes" if i == 0 else "no"} for i, e in enumerate(evidence)],
                           "expected_statements": [{"statement": "x", "supported_by_evidence": "yes"}],
                           "claims": [{"claim": "x", "supported": "yes"}], "statements": [{"statement": "x", "relevant": "yes"}]}
            else:
                try:
                    verdict = judge_call(settings, judge_model, user)
                except Exception as exc:  # noqa: BLE001 - judge model not available on this account: use the backend's model
                    code = getattr(getattr(exc, "response", None), "status_code", None)
                    if code not in (400, 403, 404) or judge_model == settings.llm_model:
                        raise
                    print(f"   judge {judge_model} unavailable ({code}); using {settings.llm_model}", flush=True)
                    verdict = judge_call(settings, settings.llm_model, user)
                    row["judge_fallback"] = settings.llm_model
            row.update(scores(verdict))
            row["verdict"] = json.dumps(verdict, ensure_ascii=False)
        except Exception as exc:  # noqa: BLE001
            row["error"] = f"{type(exc).__name__}: {exc}"
        print(f"   judged {inc.incident_id}: " + (row.get("error") or f"faithfulness={row.get('faithfulness')}"), flush=True)
        return row

    # pipeline: explain incident i while incident i-1 is being judged (different models, separate rate limits)
    futures = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for n, inc in enumerate(sample.inc, 1):
            mode = explain(inc)
            print(f"{n}/{len(sample)} {inc.incident_id} explained ({mode})", flush=True)
            futures.append(pool.submit(judge, inc))
        rows = [f.result() for f in futures]

    out = pd.DataFrame(rows)
    out.to_csv("eval_rag_judge.csv", index=False)
    ok = out[out.get("error").isna()] if "error" in out else out
    metrics = ["contextual_precision", "contextual_recall", "contextual_relevancy", "faithfulness", "answer_relevancy"]
    mean = lambda g, m: round(float(g[m].dropna().mean()), 4) if m in g and g[m].notna().any() else None
    summary = {"incidents": len(sample), "judged": len(ok), "judge_model": judge_model,
               "generator_model": settings.llm_model,
               "explanations_by_llm": int((ok["mode"] == "llm").sum()) if "mode" in ok else 0,
               **{m: mean(ok, m) for m in metrics},
               "unsupported_claims_per_explanation": round(float(ok["unsupported_claims"].mean()), 2) if len(ok) else None,
               "groundedness": mean(ok, "groundedness"),
               "when_detector_technique_right": {m: mean(ok[ok.detector_correct], m) for m in metrics},
               "when_detector_technique_wrong": {m: mean(ok[~ok.detector_correct], m) for m in metrics}}
    Path("eval_rag_judge_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
