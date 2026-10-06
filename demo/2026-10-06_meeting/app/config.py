"""Paths and constants for the threat-detection demo app.

All runtime artifacts live under app/data.
"""
from __future__ import annotations

import json
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
MODEL_DIR = DATA_DIR / "models"
GRAPH_DIR = DATA_DIR / "prepared_graphs"
RAG_INPUT_DIR = DATA_DIR / "rag_input"

EVALUATION_JSONL = RAG_INPUT_DIR / "gnn_test_events_evaluation.jsonl"
ATTACK_JSONL = RAG_INPUT_DIR / "gnn_attack_events_for_rag.jsonl"
TEST_EDGES_PARQUET = DATA_DIR / "test_edges_5min_enriched.parquet"
RAG_METADATA_PARQUET = DATA_DIR / "test_rag_metadata_5min.parquet"
RAG_DIR = DATA_DIR / "rag"
RAG_MITRE_LOOKUP = RAG_DIR / "processed" / "mitre_lookup.csv"
RAG_PROCEDURE_CHUNKS = RAG_DIR / "processed" / "procedure_chunks.jsonl"

BINARY_PATH = MODEL_DIR / "binary_graphsage_best.pt"
MITRE_PATH = MODEL_DIR / "mitre_graphsage.pt"
TACTIC_PATH = MODEL_DIR / "tactic_graphsage.pt"
TEST_GRAPHS_PATH = GRAPH_DIR / "test_graphs.pt"
BINARY_METRICS = MODEL_DIR / "binary_graphsage_v2.json"

WINDOW_MINUTES = 5
DEFAULT_BINARY_THRESHOLD = 0.8609099984169006


def load_binary_threshold() -> float:
    if BINARY_METRICS.exists():
        with BINARY_METRICS.open(encoding="utf-8") as f:
            payload = json.load(f)
        if "validation_threshold" in payload:
            return float(payload["validation_threshold"])
    return DEFAULT_BINARY_THRESHOLD


def live_inference_available() -> bool:
    required = (
        BINARY_PATH,
        MITRE_PATH,
        TACTIC_PATH,
        TEST_GRAPHS_PATH,
        TEST_EDGES_PARQUET,
    )
    return all(p.exists() for p in required)


def missing_artifacts() -> list[str]:
    checks = [
        EVALUATION_JSONL,
        BINARY_PATH,
        MITRE_PATH,
        TACTIC_PATH,
        TEST_GRAPHS_PATH,
        TEST_EDGES_PARQUET,
        RAG_METADATA_PARQUET,
        BINARY_METRICS,
        RAG_MITRE_LOOKUP,
        RAG_PROCEDURE_CHUNKS,
    ]
    return [str(path.relative_to(APP_DIR)) for path in checks if not path.exists()]
