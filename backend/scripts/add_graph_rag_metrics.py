"""Merge the GraphRAG evaluation into metrics.json (shown on the Evaluation page, RAG tab).

Run from the backend folder after the evaluations:
    python scripts/eval_graph_retrieval.py                       # no LLM needed
    python scripts/eval_rag_judge.py --retriever graph           # optional, needs the Groq key
    python scripts/add_graph_rag_metrics.py                      # writes data/metrics.json (or METRICS_FILE)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "scripts"))

JUDGE_KEYS = ["contextual_precision", "contextual_recall", "contextual_relevancy", "faithfulness", "answer_relevancy"]


def judge_block(summary: dict) -> dict:
    return {"incidents": summary.get("incidents"), "judge_model": summary.get("judge_model"),
            "generator_model": summary.get("generator_model"),
            "all": {k: summary.get(k) for k in JUDGE_KEYS},
            "technique_right": summary.get("when_detector_technique_right"),
            "technique_wrong": summary.get("when_detector_technique_wrong"),
            "unsupported_claims_per_explanation": summary.get("unsupported_claims_per_explanation"),
            "groundedness": summary.get("groundedness")}


def main() -> None:
    from eval_explanations import load_env
    load_env(HERE / ".env")
    from app.config import Settings

    settings = Settings.from_env()
    target = settings.metrics_file if settings.metrics_file and "metrics.default" not in str(settings.metrics_file) \
        else HERE / "data" / "metrics.json"
    metrics = json.loads(Path(target).read_text()) if Path(target).exists() else {}
    retrieval = json.loads(Path("eval_graph_retrieval.json").read_text())
    block = {"method": "GraphRAG over the MITRE ATT&CK knowledge graph: Personalized PageRank from the predicted "
                       "technique; graph facts plus text found along the selected relations",
             "references": ["Peng et al. 2024, Graph Retrieval-Augmented Generation: A Survey (arXiv:2408.08921)",
                            "Han et al. 2025, Retrieval-Augmented Generation with Graphs (GraphRAG) (arXiv:2501.00309)",
                            "Edge et al. 2024, From Local to Global: A Graph RAG Approach (arXiv:2404.16130)"],
             "knowledge_graph": retrieval["graph"], "store": retrieval.get("store"),
             "retrieval": {"all_labelled": retrieval["all_labelled"], "judge_sample_50": retrieval["judge_sample_50"]}}
    judged = Path("eval_rag_judge_graph_summary.json")
    if judged.exists():
        block["rag_judge"] = judge_block(json.loads(judged.read_text()))
    vector = Path("eval_rag_judge_vector_summary.json")
    if vector.exists():
        block["rag_judge_vector"] = judge_block(json.loads(vector.read_text()))
    reranked = Path("eval_rag_judge_graph_rerank_summary.json")
    if reranked.exists():
        block["rag_judge_rerank"] = {**judge_block(json.loads(reranked.read_text())),
                                     "rerank_model": json.loads(reranked.read_text()).get("rerank_model")}
    metrics["graph_rag"] = block
    Path(target).write_text(json.dumps(metrics, indent=2))
    print(f"Updated {target}: graph_rag ({'with' if 'rag_judge' in block else 'without'} the LLM-judge results)")


if __name__ == "__main__":
    main()
