"""Public RAG API for the Streamlit app."""
from __future__ import annotations

from typing import Any

from app.rag.gnn_bridge import gnn_output_to_events
from app.rag.reason import generate_reasoning
from app.rag.retrieve import RAGEngine, RetrievalResult


def explain_attack_event(
    gnn_event: dict[str, Any],
    engine: RAGEngine,
    api_key: str | None = None,
    model: str | None = None,
) -> dict[str, Any]:
    """Run retrieve + Groq/local reasoning for one GNN attack event."""
    query_events = gnn_output_to_events(gnn_event)
    if not query_events:
        return {
            "reasoning": "",
            "mode": "skipped",
            "technique_id": None,
            "sources": [],
            "source_count": 0,
            "source_summary": "",
            "retrieval": None,
        }

    primary = query_events[0]
    result: RetrievalResult = engine.retrieve(primary)
    explanation = generate_reasoning(
        primary,
        result,
        api_key=api_key,
        model=model,
    )
    explanation["query_events"] = query_events
    explanation["retrieval"] = {
        "cve_mode": result.cve_mode,
        "tactics": result.tactics,
        "n_cti": len(result.cti),
        "n_cve": len(result.cve),
        "mitre_name": (result.mitre or {}).get("name"),
    }
    return explanation


__all__ = [
    "RAGEngine",
    "explain_attack_event",
    "generate_reasoning",
    "gnn_output_to_events",
]
