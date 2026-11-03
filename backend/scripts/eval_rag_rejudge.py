"""Re-judge Faithfulness for the explanations scored by eval_rag_judge.py, with the full incident input.

The first judge prompt left out the detector's attack probability, the ports and the behaviour check, so
claims based on them were marked unsupported. This script rebuilds exactly what the explanation LLM saw
(incident brief incl. behaviour-check disagreement, and the numbered evidence; both are deterministic),
takes each explanation's claims from eval_rag_judge.csv, and asks the judge again. No explanation is
regenerated, so only the judge model is called.

    python scripts/eval_rag_rejudge.py            # reads eval_rag_judge.csv, updates eval_rag_judge_summary.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "scripts"))

PROMPT = """You check whether each claim in an explanation of a network-security incident is supported.
INCIDENT is the record the explanation was written from (it includes the detector's attack probability and,
if present, a behaviour check that suggests other techniques). EVIDENCE is the retrieved evidence.
A claim is "yes" if it is stated in or directly implied by INCIDENT or EVIDENCE, "no" if it contradicts them,
"idk" if neither supports nor contradicts it. Return JSON: {"claims": [{"claim": "...", "supported": "yes"|"no"|"idk"}]}
with the claims in the given order."""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", default="eval_rag_judge.csv")
    parser.add_argument("--judge-model", default=None)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    from eval_explanations import load_env
    load_env(HERE / ".env")

    import pandas as pd
    import requests
    from fastapi.testclient import TestClient
    from app.behavior import event_fields
    from app.explain import incident_brief, retrieval_query
    from app.main import create_app
    from eval_rag_judge import retry, scores, yes

    rows = pd.read_csv(args.csv)
    app = create_app()
    st = app.state.app_state
    settings, kb, ex = st.settings, st.kb, st.explanations
    judge_model = args.judge_model or (rows.get("judge_fallback").dropna().iloc[0] if "judge_fallback" in rows and rows["judge_fallback"].notna().any()
                                       else ("openai/gpt-oss-120b" if settings.llm_provider == "groq" else settings.llm_model))
    c = TestClient(app, headers={"X-API-Key": settings.api_key})
    print("Running detection over the test split (no LLM calls)...", flush=True)
    c.post("/detect", json={"reset": True})
    while c.post("/detect", json={}).status_code == 200:
        pass
    incidents = st.controller.state.incidents

    def rebuild(inc):
        """The same brief and evidence ExplanationManager._start builds for the LLM."""
        brief = incident_brief(inc, kb)
        features = ex._features(inc)
        event = event_fields(features) if features is not None else None
        r = kb.retrieve(brief["technique_id"], brief["tactic"], retrieval_query(brief), settings.retrieval_top_k,
                        settings.retrieval_min_score, event=event)
        if features is not None and ex.behavior is not None and ex.behavior.enabled:
            check = ex.behavior.check(features, brief["technique_id"])
            if check and check["agrees_with_detector"] is False:
                brief["behavior_check"] = {k: check[k] for k in ("reading", "candidates", "agrees_with_detector")}
        evidence = [{k: e[k] for k in ("evidence_id", "source", "title", "text")} for e in r.evidence]
        return brief, evidence

    def judge(user):
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {settings.llm_api_key}"}
        body = {"model": judge_model, "temperature": 0, "max_tokens": 1500, "response_format": {"type": "json_object"},
                "messages": [{"role": "system", "content": PROMPT}, {"role": "user", "content": user}]}
        if judge_model.startswith("openai/gpt-oss"):
            body["reasoning_effort"] = "low"

        def call():
            r = requests.post(f"{settings.llm_base_url.rstrip('/')}/chat/completions", headers=headers, json=body,
                              timeout=max(settings.llm_timeout_s, 90))
            r.raise_for_status()
            text = r.json()["choices"][0]["message"]["content"] or ""
            return json.loads(text[text.find("{"): text.rfind("}") + 1])
        return retry(call)

    new = []
    for i, row in rows.iterrows():
        if not isinstance(row.get("verdict"), str):
            new.append(None)
            continue
        verdict = json.loads(row["verdict"])
        claims = [cl.get("claim", "") for cl in verdict.get("claims") or []]
        brief, evidence = rebuild(incidents[row["incident_id"]])
        if args.dry_run:
            result = {"claims": [{"claim": cl, "supported": "yes"} for cl in claims]}
        else:
            result = judge(json.dumps({"INCIDENT": brief, "EVIDENCE": evidence, "CLAIMS": claims}, ensure_ascii=False))
        verdict["claims"] = result.get("claims") or verdict.get("claims")
        s = scores(verdict)
        rows.loc[i, "faithfulness_first_pass"] = row.get("faithfulness")
        rows.loc[i, "faithfulness"] = s["faithfulness"]
        rows.loc[i, "unsupported_claims"] = s["unsupported_claims"]
        rows.loc[i, "verdict"] = json.dumps(verdict, ensure_ascii=False)
        print(f"{i + 1}/{len(rows)} {row['incident_id']}: faithfulness {row.get('faithfulness')} -> {s['faithfulness']}", flush=True)

    rows.to_csv(args.csv, index=False)
    summary_path = Path("eval_rag_judge_summary.json")
    summary = json.loads(summary_path.read_text()) if summary_path.exists() else {}
    ok = rows[rows["faithfulness"].notna()]
    mean = lambda g: round(float(g["faithfulness"].mean()), 4) if len(g) else None
    summary.update({
        "faithfulness": mean(ok),
        "faithfulness_first_pass": round(float(ok["faithfulness_first_pass"].mean()), 4) if "faithfulness_first_pass" in ok else None,
        "unsupported_claims_per_explanation": round(float(ok["unsupported_claims"].mean()), 2),
        "faithfulness_judge": judge_model,
    })
    for key, part in (("when_detector_technique_right", ok[ok.detector_correct.astype(str) == "True"]),
                      ("when_detector_technique_wrong", ok[ok.detector_correct.astype(str) != "True"])):
        summary.setdefault(key, {})["faithfulness"] = mean(part)
    summary_path.write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
