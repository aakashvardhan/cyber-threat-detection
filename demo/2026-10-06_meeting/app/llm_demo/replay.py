"""Load the saved Gemma 4 runs, score them, and assemble live prompts from the private config."""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from functools import lru_cache

import numpy as np
import pandas as pd

from app.config import LLM_EVAL_DIR, TEST_EDGES_PARQUET
from app.llm_demo import prompts
from app.llm_demo.serializer import event_record, serialize_event_json

SUFFIX = "ip_models-gemma-4-31b-it"
# run name -> (file prefix, few-shot draw or None for zero-shot)
RUNS = {
    "Zero-shot": ("zero", None),
    "Few-shot (draw 0)": ("few4-validation-s0", 0),
    "Few-shot (draw 1)": ("few4-validation-s1", 1),
    "Few-shot (draw 2)": ("few4-validation-s2", 2),
}
THOUGHT = re.compile(r"<thought>.*?</thought>", flags=re.S)
DROPPED_KEYS = ("gnn_detection", "ground_truth")


@dataclass(frozen=True)
class Reply:
    edge_idx: int
    y: int | None
    pred: int | None
    technique: str | None
    true_techniques: list[str]
    raw: str

    @property
    def answer(self) -> str:
        """The model's final answer; the reasoning block is never shown."""
        return THOUGHT.sub("", self.raw).strip()


@lru_cache(maxsize=1)
def test_edges() -> pd.DataFrame:
    return pd.read_parquet(TEST_EDGES_PARQUET)


@lru_cache(maxsize=None)
def load_run(run: str) -> dict[int, Reply]:
    prefix, _ = RUNS[run]
    path = LLM_EVAL_DIR / f"{prefix}_{SUFFIX}.jsonl"
    out = {}
    for line in path.read_text().splitlines():
        d = json.loads(line)
        out[int(d["edge_idx"])] = Reply(int(d["edge_idx"]), int(d["y"]), d["pred"], d["technique"],
                                        list(d["true_techniques"]), d["raw"])
    return out


def edge_row(edge_idx: int) -> pd.Series:
    return test_edges().loc[edge_idx]


def draw_of(run: str) -> int | None:
    return RUNS[run][1]


def prompt_for(cfg: dict, run: str, edge_idx: int) -> str:
    """Prompt sent live for a test edge, built from the private config."""
    return prompts.build_prompt(cfg, draw_of(run), event_record(edge_row(edge_idx), edge_idx, "test"))


def prompt_for_record(cfg: dict, run: str, record: dict) -> str:
    return prompts.build_prompt(cfg, draw_of(run), record)


def target_event_text(edge_idx: int) -> str:
    return serialize_event_json(edge_row(edge_idx), edge_idx, "test")


def parse_custom_event(text: str) -> tuple[dict, list[str]]:
    """Turn pasted JSON into a clean event record. Returns (record, ignored top-level keys).

    Accepts a full record (event_id, row_id, event, ...) or a bare event ({"traffic_features": ...}).
    gnn_detection and ground_truth are always dropped so they can never reach the model.
    """
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"That is not valid JSON (line {e.lineno}, column {e.colno}: {e.msg}).") from None
    if not isinstance(obj, dict):
        raise ValueError("Paste a single JSON object, not a list or a bare value.")
    if "event" not in obj:
        if "traffic_features" not in obj:
            raise ValueError('Expected an object with an "event" block (or "traffic_features" at the top level).')
        obj = {"event": obj}
    if not isinstance(obj["event"], dict) or not isinstance(obj["event"].get("traffic_features"), dict):
        raise ValueError('"event" must contain a "traffic_features" object.')
    ignored = [k for k in DROPPED_KEYS if k in obj]
    record = {"event_id": obj.get("event_id", "custom-event"), "row_id": obj.get("row_id", 0), "event": obj["event"]}
    return record, ignored


def common_edges() -> list[int]:
    """Edge ids scored by every run (the shared 400-edge sample)."""
    sets = [set(load_run(r)) for r in RUNS]
    return sorted(set.intersection(*sets))


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return float("nan"), float("nan")
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return c - h, c + h


def _parent(code):
    return code.split(".")[0] if isinstance(code, str) else None


def run_metrics(run: str, prevalence: float) -> dict:
    """Recall, FPR, projected precision/F1 and technique accuracy for one saved run.

    Unparseable replies count as "attack" (a missed attack costs more than a false alarm).
    """
    replies = list(load_run(run).values())
    y = np.array([r.y for r in replies])
    yhat = np.array([1 if r.pred is None else r.pred for r in replies])
    n_att, n_norm = int((y == 1).sum()), int((y == 0).sum())
    tp, fp = int(((yhat == 1) & (y == 1)).sum()), int(((yhat == 1) & (y == 0)).sum())
    tpr, fpr = tp / n_att, fp / n_norm
    d = tpr * prevalence + fpr * (1 - prevalence)
    prec = tpr * prevalence / d if d > 0 else float("nan")
    hits = [r for r in replies if r.y == 1 and r.pred == 1 and r.true_techniques]
    tech = (np.mean([_parent(r.technique) in {_parent(t) for t in r.true_techniques} for r in hits])
            if hits else float("nan"))
    return dict(run=run, recall=tpr, recall_ci=wilson(tp, n_att), fpr=fpr, fpr_ci=wilson(fp, n_norm),
                precision=prec, f1=2 * prec * tpr / (prec + tpr) if prec + tpr > 0 else float("nan"),
                technique_acc=tech, n=len(replies), unusable=sum(r.pred is None for r in replies))


def test_prevalence() -> float:
    return float(test_edges().binary_target.mean())


def label_text(pred: int | None) -> str:
    return {1: "attack", 0: "normal"}.get(pred, "unparseable")
