"""Load precomputed combined-inference JSON grouped by 5-minute window."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pandas as pd

from app.config import EVALUATION_JSONL, WINDOW_MINUTES


@dataclass(frozen=True)
class WindowSummary:
    window_start: str
    window_end: str
    total_events: int
    attack_events: int


def parse_window_start(value: str) -> datetime:
    text = value.replace("Z", "+00:00")
    if "T" in text:
        return datetime.fromisoformat(text)
    return datetime.fromisoformat(text)


def window_interval_label(window_start: str) -> tuple[str, str]:
    start = parse_window_start(window_start)
    end = start + timedelta(minutes=WINDOW_MINUTES)
    return start.isoformat(sep=" "), end.isoformat(sep=" ")


def load_evaluation_index(
    jsonl_path: Path | None = None,
) -> tuple[list[str], dict[str, list[dict[str, Any]]], list[WindowSummary]]:
    path = jsonl_path or EVALUATION_JSONL
    if not path.exists():
        raise FileNotFoundError(
            f"Evaluation JSONL not found: {path}. "
            "Expected file at app/data/rag_input/gnn_test_events_evaluation.jsonl."
        )

    windows_ordered: list[str] = []
    seen: set[str] = set()
    by_window: dict[str, list[dict[str, Any]]] = {}

    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            record = json.loads(line)
            window_start = record["event"]["window_start"]
            if window_start not in seen:
                seen.add(window_start)
                windows_ordered.append(window_start)
            by_window.setdefault(window_start, []).append(record)

    summaries: list[WindowSummary] = []
    for window_start in windows_ordered:
        events = by_window[window_start]
        attacks = sum(
            1
            for event in events
            if event["gnn_detection"]["binary_prediction"]["label"] == "attack"
        )
        start_label, end_label = window_interval_label(window_start)
        summaries.append(
            WindowSummary(
                window_start=start_label,
                window_end=end_label,
                total_events=len(events),
                attack_events=attacks,
            )
        )

    return windows_ordered, by_window, summaries


def events_to_summary_table(
    events: list[dict[str, Any]],
    rag_by_event_id: dict[str, dict[str, Any]] | None = None,
) -> pd.DataFrame:
    rag_by_event_id = rag_by_event_id or {}
    rows = []
    for event in events:
        detection = event["gnn_detection"]["binary_prediction"]
        tactic = event["gnn_detection"].get("tactic_prediction") or {}
        mitre_candidates = event["gnn_detection"].get("mitre_candidates") or []
        mitre_top = mitre_candidates[0] if mitre_candidates else {}
        rag = rag_by_event_id.get(event["event_id"], {})
        rows.append(
            {
                "Event ID": event["event_id"],
                "Source IP": event["event"]["source_ip"],
                "Destination IP": event["event"]["destination_ip"],
                "Prediction": detection["label"],
                "Attack Probability": detection["attack_probability"],
                "Binary Confidence": detection["confidence"],
                "MITRE Technique": event["gnn_detection"].get("selected_mitre_id"),
                "MITRE Confidence": mitre_top.get("confidence"),
                "Tactic": tactic.get("label"),
                "Tactic Confidence": tactic.get("confidence"),
                "RAG Reasoning": rag.get("reasoning", ""),
                "RAG Sources": rag.get("source_count", 0) or rag.get("source_summary", ""),
            }
        )
    return pd.DataFrame(rows)
