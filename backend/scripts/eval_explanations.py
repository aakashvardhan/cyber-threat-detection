"""Batch statistics for the LLM explanations (groundedness, citations, latency).

Run from the backend folder, with the same .env the backend uses (it is read here):
    python scripts/eval_explanations.py --n 100

It replays the whole test split, samples N incidents (seed 42, spread over the detector's techniques),
asks the backend for each explanation exactly as the app does, and writes
    eval_explanations.csv          one row per incident
    eval_explanations_summary.json the averages
Nothing is sent anywhere except the LLM calls the app already makes.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))


def load_env(path: Path) -> None:
    for name in [k for k in os.environ if k.startswith("LLM_")]:
        del os.environ[name]                      # same as start-backend.ps1: .env decides the LLM
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ[key.strip()] = value.strip()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, default=100)
    parser.add_argument("--timeout", type=float, default=90, help="seconds to wait for one explanation")
    args = parser.parse_args()
    load_env(HERE / ".env")

    import pandas as pd
    from fastapi.testclient import TestClient
    from app.main import create_app

    app = create_app()
    key = os.environ.get("API_KEY", "")
    c = TestClient(app, headers={"X-API-Key": key})
    print("Replaying the test split...", flush=True)
    c.post("/detect", json={"reset": True})
    while c.post("/detect", json={}).status_code == 200:
        pass
    incidents = pd.DataFrame(c.get("/incidents").json()["incidents"])
    print(f"{len(incidents)} incidents; LLM provider: {app.state.app_state.settings.llm_provider}", flush=True)

    # spread the sample over techniques, in proportion, at least 2 per technique where possible
    share = incidents.technique_id.value_counts(normalize=True)
    picks = []
    for technique, frac in share.items():
        group = incidents[incidents.technique_id == technique]
        k = min(len(group), max(2, round(frac * args.n)))
        picks.append(group.sample(k, random_state=42))
    sample = pd.concat(picks).head(args.n)

    rows = []
    for i, inc in enumerate(sample.itertuples(), 1):
        started = time.time()
        while True:
            d = c.get(f"/incidents/{inc.incident_id}").json()
            ex = d["explanation"]
            if ex["status"] != "generating" or time.time() - started > args.timeout:
                break
            time.sleep(1)
        sentences = ex.get("sentences") or []
        cited = [s for s in sentences if s.get("citations")]
        evidence = {e["evidence_id"]: e for e in d.get("evidence", [])}
        used = {cid for s in sentences for cid in s.get("citations", [])}
        trace = d.get("retrieval_trace") or {}
        check = trace.get("behavior_check") or {}
        rows.append({
            "incident_id": inc.incident_id, "technique_id": inc.technique_id, "status": ex["status"],
            "mode": ex.get("mode"), "model": ex.get("model"), "latency_s": (ex.get("latency_ms") or 0) / 1000,
            "sentences": len(sentences), "cited_sentences": len(cited), "groundedness": ex.get("groundedness"),
            "evidence_retrieved": len(evidence), "evidence_cited": len(used & set(evidence)),
            "cited_sources": ",".join(sorted({evidence[x]["source"] for x in used if x in evidence})),
            "behaviour_agrees": check.get("agrees_with_detector"), "message": ex.get("message"),
        })
        print(f"{i}/{len(sample)} {inc.incident_id} {ex['status']} {ex.get('mode')} groundedness={ex.get('groundedness')}", flush=True)

    out = pd.DataFrame(rows)
    out.to_csv("eval_explanations.csv", index=False)
    llm = out[(out.status == "ready") & (out["mode"] == "llm")]
    summary = {
        "incidents": len(out), "llm_explanations": len(llm),
        "fallback_or_error": int(len(out) - len(llm)),
        "groundedness_mean": round(float(llm.groundedness.mean()), 4) if len(llm) else None,
        "groundedness_median": round(float(llm.groundedness.median()), 4) if len(llm) else None,
        "fully_grounded_share": round(float((llm.groundedness == 1).mean()), 4) if len(llm) else None,
        "sentences_mean": round(float(llm.sentences.mean()), 2) if len(llm) else None,
        "evidence_cited_share": round(float((llm.evidence_cited / llm.evidence_retrieved.clip(lower=1)).mean()), 4) if len(llm) else None,
        "latency_s_mean": round(float(llm.latency_s.mean()), 2) if len(llm) else None,
        "latency_s_p90": round(float(llm.latency_s.quantile(0.9)), 2) if len(llm) else None,
        "cited_source_share": {s: round(float(llm.cited_sources.str.contains(s).mean()), 4)
                               for s in ("mitre", "procedure", "cti", "cve")} if len(llm) else None,
        "model": llm.model.iloc[0] if len(llm) else None,
    }
    Path("eval_explanations_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
