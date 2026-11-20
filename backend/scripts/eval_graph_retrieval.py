"""GraphRAG vs the vector retriever, without an LLM: does the retrieved context reach the true technique?

Run from the backend folder (same .env as the backend):
    python scripts/eval_graph_retrieval.py            # all labelled incidents + the 50-incident judge sample

For every labelled test incident both retrievers get exactly the input the console gives them (incident brief,
traffic features, behaviour check, earlier incidents from the same source). Metrics, split by whether the
detector's technique is right:
  true technique in context   the context names a ground-truth technique (ID or name)
  next-step hit               (graph only) a ground-truth technique is among the "what these actors also do"
  context items, latency      size of the context and retrieval time
Writes eval_graph_retrieval.json.
"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "scripts"))


def main() -> None:
    from eval_explanations import load_env
    load_env(HERE / ".env")
    import numpy as np
    import pandas as pd
    from fastapi.testclient import TestClient
    from app.behavior import event_fields
    from app.explain import incident_brief, retrieval_query
    from app.main import create_app, earlier_incidents

    app = create_app()
    st = app.state.app_state
    if st.graph_rag is None:
        sys.exit("GraphRAG is off (RETRIEVER=graph and an ATT&CK STIX file are needed)")
    kb, data, settings, ex = st.kb, st.replay_data, st.settings, st.explanations
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
    sample_ids = set(pd.concat([frame[frame.technique == t].sample(min((frame.technique == t).sum(), max(2, round(f * 50))),
                                                                   random_state=42) for t, f in share.items()]).head(50).inc.map(lambda i: i.incident_id))

    def mentions(items, truth):
        blob = " ".join(f"{e.get('ref', '')} {e.get('title', '')} {e.get('text', '')}" for e in items)
        names = {t: kb.technique_name(t) for t in truth}
        return any(re.search(rf"\b{t}\b", blob) or (names[t] != t and names[t].lower() in blob.lower()) for t in truth)

    rows = []
    for n, inc in enumerate(incidents, 1):
        truth = truth_of(inc)
        brief = incident_brief(inc, kb)
        features = ex._features(inc)
        event = event_fields(features) if features is not None else None
        check = ex.behavior.check(features, brief["technique_id"]) if features is not None and ex.behavior and ex.behavior.enabled else None
        alts = [x["technique_id"] for x in check["candidates"][:2]] if check and check["agrees_with_detector"] is False else []
        history = ex._history(inc) if ex.history else []
        t0 = time.perf_counter()
        g = st.graph_rag.retrieve(brief["technique_id"], brief["tactic"], retrieval_query(brief), settings.retrieval_top_k,
                                  event=event, alternatives=alts, history=history)
        t1 = time.perf_counter()
        v = kb.retrieve(brief["technique_id"], brief["tactic"], retrieval_query(brief), settings.retrieval_top_k,
                        settings.retrieval_min_score, event=event)
        t2 = time.perf_counter()
        nxt = {n_["id"] for n_ in g.trace["graph"]["nodes"] if n_["role"] == "next"}
        rows.append({"incident_id": inc.incident_id, "sample": inc.incident_id in sample_ids,
                     "detector_correct": inc.technique_id.split(".")[0] in truth, "truth": ",".join(sorted(truth)),
                     "graph_hit": mentions(g.evidence, truth), "vector_hit": mentions(v.evidence, truth),
                     "graph_next_hit": bool(nxt & truth), "graph_items": len(g.evidence), "vector_items": len(v.evidence),
                     "graph_ms": (t1 - t0) * 1000, "vector_ms": (t2 - t1) * 1000, "has_alternative": bool(alts),
                     "has_history": bool(history)})
        if n % 200 == 0:
            print(f"{n}/{len(incidents)}", flush=True)

    out = pd.DataFrame(rows)

    def block(d):
        def part(x):
            return {"incidents": int(len(x)),
                    "true_technique_in_context": {"graph": round(float(x.graph_hit.mean()), 4) if len(x) else None,
                                                  "vector": round(float(x.vector_hit.mean()), 4) if len(x) else None},
                    "graph_next_step_hit": round(float(x.graph_next_hit.mean()), 4) if len(x) else None}
        return {"all": part(d), "technique_right": part(d[d.detector_correct]), "technique_wrong": part(d[~d.detector_correct]),
                "context_items": {"graph": round(float(d.graph_items.mean()), 2), "vector": round(float(d.vector_items.mean()), 2)},
                "latency_ms_median": {"graph": round(float(d.graph_ms.median()), 1), "vector": round(float(d.vector_ms.median()), 1)},
                "with_behaviour_alternative": round(float(d.has_alternative.mean()), 4),
                "with_earlier_incidents": round(float(d.has_history.mean()), 4)}

    summary = {"store": st.graph_rag.store.name, "graph": st.graph_rag.graph.stats(),
               "all_labelled": block(out), "judge_sample_50": block(out[out["sample"]])}
    out.to_csv("eval_graph_retrieval.csv", index=False)
    Path("eval_graph_retrieval.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
