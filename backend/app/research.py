"""Offline outputs for the Research tab and GET /metrics.

model_outputs.jsonl: one JSON object per (edge, model) with event_id (or window_start +
src_ip_zeek + dest_ip_zeek), model, label, attack_probability, technique_id, confidence,
explanation_text, groundedness. Models 1-5 are precomputed for the test split.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

from app.replay_data import ReplayData
from app.timeutil import to_naive_utc


class ModelOutputs:
    def __init__(self, by_event: dict[str, list[dict]] | None = None, source: str | None = None):
        self.by_event = by_event or {}
        self.source = source

    @classmethod
    def load(cls, path: Path | None, replay: ReplayData) -> "ModelOutputs":
        if path is None or not Path(path).exists():
            return cls()
        key_to_event = {(w, s, d): e for w, s, d, e in replay.frame[
            ["window_start", "src_ip_zeek", "dest_ip_zeek", "event_id"]].itertuples(index=False)}
        by_event: dict[str, list[dict]] = defaultdict(list)
        with Path(path).open(encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                row = json.loads(line)
                event = row.get("event_id") or key_to_event.get(
                    (to_naive_utc(row["window_start"]), row.get("src_ip_zeek"), row.get("dest_ip_zeek")))
                if event:
                    by_event[event].append(row)
        return cls(dict(by_event), str(path))

    def for_incident(self, event_ids: list[str]) -> list[dict]:
        grouped: dict[str, list[dict]] = defaultdict(list)
        for event in event_ids:
            for row in self.by_event.get(event, []):
                grouped[row["model"]].append(row)
        outputs = []
        for model in sorted(grouped):
            rows = grouped[model]
            probabilities = [r["attack_probability"] for r in rows if r.get("attack_probability") is not None]
            techniques = Counter(r["technique_id"] for r in rows if r.get("technique_id"))
            confidences = [r["confidence"] for r in rows if r.get("confidence") is not None]
            grounded = [r["groundedness"] for r in rows if r.get("groundedness") is not None]
            text = next((r["explanation_text"] for r in rows if r.get("explanation_text")), None)
            output = {
                "model": model,
                "label": "attack" if any(r.get("label") == "attack" for r in rows) else "normal",
                "attack_probability": round(max(probabilities), 4) if probabilities else None,
                "technique_id": techniques.most_common(1)[0][0] if techniques else None,
                "confidence": round(sum(confidences) / len(confidences), 4) if confidences else None,
                "groundedness": round(sum(grounded) / len(grounded), 4) if grounded else None,
            }
            if text:
                output["explanation_text"] = text
            outputs.append(output)
        return outputs


def load_metrics(path: Path | None) -> dict:
    if path is None or not Path(path).exists():
        return {"primary_model": "unknown", "models": []}
    with Path(path).open(encoding="utf-8") as handle:
        return json.load(handle)
