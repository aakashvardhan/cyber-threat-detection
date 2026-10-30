"""Replay state and incident grouping.

Grouping rule (API contract): an attack edge joins an open incident with the same source_ip and
the same top technique if that incident's last window is less than INCIDENT_GAP_MINUTES earlier;
otherwise it starts a new incident.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from app.detectors import Detector, Prediction
from app.knowledge import KnowledgeBase
from app.replay_data import ReplayData
from app.timeutil import iso

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


class ReplayError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


@dataclass
class EdgeRecord:
    row: int
    event_id: str
    window_start: pd.Timestamp
    source_ip: str
    destination_ip: str
    attack_probability: float
    service: str | None
    port: int | None
    technique_probs: dict[str, float]
    tactic_probs: dict[str, float]
    severity: str | None


@dataclass
class Incident:
    incident_id: str
    source_ip: str
    technique_id: str
    edges: list[EdgeRecord] = field(default_factory=list)
    status: str = "new"
    technique_override: str | None = None
    mitigations_applied: list[str] = field(default_factory=list)
    activity: list[dict] = field(default_factory=list)
    # explanation state (managed by app.explain)
    explanation: dict | None = None
    evidence: list[dict] = field(default_factory=list)
    retrieval_trace: dict | None = None
    cve_status: str = "not_applicable"

    @property
    def last_window(self) -> pd.Timestamp:
        return max(e.window_start for e in self.edges)

    @property
    def first_window(self) -> pd.Timestamp:
        return min(e.window_start for e in self.edges)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    @property
    def effective_technique(self) -> str:
        return self.technique_override or self.technique_id

    def mean_probs(self, attribute: str) -> dict[str, float]:
        totals: dict[str, float] = {}
        for edge in self.edges:
            for label, value in getattr(edge, attribute).items():
                totals[label] = totals.get(label, 0.0) + value
        return {label: value / len(self.edges) for label, value in totals.items()}

    def tactic(self, kb: KnowledgeBase) -> tuple[str, float]:
        probs = self.mean_probs("tactic_probs")
        if probs:
            label = max(probs, key=probs.get)
            return label, probs[label]
        tactics = kb.tactics_of(self.effective_technique)
        return (tactics[0] if tactics else "Unknown"), 0.0

    def severity(self) -> str | None:
        ranked = [e.severity for e in self.edges if e.severity in SEVERITY_RANK]
        return max(ranked, key=SEVERITY_RANK.get) if ranked else None


HIGH_CONFIDENCE = 0.80   # attack probability for "high-confidence" (the console's urgent level)


@dataclass
class WindowResult:
    window_start: pd.Timestamp
    events: int
    attack_edges: int
    new_incident_ids: list[str]
    updated_incident_ids: list[str]
    probabilities: np.ndarray | None = None      # per edge, in data.rows(window) order (for the graph view)
    high_confidence_edges: int = 0                # flagged edges with probability >= HIGH_CONFIDENCE


class ReplayState:
    def __init__(self, data: ReplayData, detector: Detector, gap_minutes: int):
        self.data = data
        self.detector = detector
        self.gap = pd.Timedelta(minutes=gap_minutes)
        self.results: dict[pd.Timestamp, WindowResult] = {}
        self.order: list[pd.Timestamp] = []
        self.incidents: dict[str, Incident] = {}
        self.open_by_key: dict[tuple[str, str], str] = {}
        self.counter = 0

    @property
    def last_window(self) -> pd.Timestamp | None:
        return self.order[-1] if self.order else None

    def next_after(self, window: pd.Timestamp | None) -> pd.Timestamp | None:
        if window is None:
            return self.data.windows[0] if self.data.windows else None
        position = self.data.window_position[window] + 1
        return self.data.windows[position] if position < len(self.data.windows) else None

    def response(self, window: pd.Timestamp, already: bool) -> dict:
        result = self.results[window]
        following = self.next_after(window)
        return {
            "window_start": iso(window), "next_window_start": iso(following), "already_processed": already,
            "window_index": self.data.window_position[window] + 1, "window_count": len(self.data),
            "events": result.events, "attack_edges": result.attack_edges,
            "new_incident_ids": result.new_incident_ids, "updated_incident_ids": result.updated_incident_ids,
        }

    def process(self, window: pd.Timestamp) -> WindowResult:
        rows = self.data.rows(window)
        prediction: Prediction = self.detector.predict(rows)
        threshold = self.detector.threshold
        new_ids, updated_ids = [], []

        for i, (row_index, row) in enumerate(rows.iterrows()):
            probability = float(prediction.attack_probability[i])
            if probability < threshold:
                continue
            technique_probs = (dict(zip(prediction.technique_classes, map(float, prediction.technique_probs[i])))
                               if prediction.technique_probs is not None and len(prediction.technique_classes) else {})
            tactic_probs = (dict(zip(prediction.tactic_classes, map(float, prediction.tactic_probs[i])))
                            if prediction.tactic_probs is not None and len(prediction.tactic_classes) else {})
            top = max(technique_probs, key=technique_probs.get) if technique_probs else "unknown"
            edge = EdgeRecord(
                row=int(row_index), event_id=row["event_id"], window_start=window,
                source_ip=str(row["src_ip_zeek"]), destination_ip=str(row["dest_ip_zeek"]),
                attack_probability=probability, service=self.data.service(row), port=self.data.port(row),
                technique_probs=technique_probs, tactic_probs=tactic_probs,
                severity=prediction.severity[i] if prediction.severity else None,
            )
            key = (edge.source_ip, top)
            incident = self.incidents.get(self.open_by_key.get(key, ""))
            if incident is not None and timedelta_ok(window - incident.last_window, self.gap):
                incident.edges.append(edge)
                if incident.incident_id not in new_ids and incident.incident_id not in updated_ids:
                    updated_ids.append(incident.incident_id)
            else:
                self.counter += 1
                incident = Incident(f"INC-{self.counter:04d}", edge.source_ip, top, [edge])
                self.incidents[incident.incident_id] = incident
                self.open_by_key[key] = incident.incident_id
                new_ids.append(incident.incident_id)

        probs = np.asarray(prediction.attack_probability, dtype=float)
        attack_edges = int((probs >= threshold).sum())
        high = int((probs >= max(threshold, HIGH_CONFIDENCE)).sum())   # a subset of the flagged edges
        result = WindowResult(window, len(rows), attack_edges, new_ids, updated_ids, probs, high)
        self.results[window] = result
        self.order.append(window)
        return result


def timedelta_ok(delta: pd.Timedelta, gap: pd.Timedelta) -> bool:
    return pd.Timedelta(0) <= delta < gap


class ReplayController:
    """Thread-safe front for POST /detect: idempotent windows, atomic reset."""

    def __init__(self, data: ReplayData, detector: Detector, gap_minutes: int):
        self.data, self.detector, self.gap_minutes = data, detector, gap_minutes
        self.state = ReplayState(data, detector, gap_minutes)
        self.lock = threading.Lock()

    def detect(self, window_start=None, reset: bool = False) -> dict:
        with self.lock:
            if not len(self.data):
                raise ReplayError(400, "The replay data has no windows")
            if window_start is not None:
                window = self.data.resolve(window_start)
                if window is None:
                    raise ReplayError(400, f"{window_start} is not a window in the test split")
            else:
                window = None

            if reset:
                fresh = ReplayState(self.data, self.detector, self.gap_minutes)
                target = window or self.data.windows[0]
                fresh.process(target)          # raises before the swap if processing fails
                self.state = fresh
                return fresh.response(target, already=False)

            state = self.state
            if window is None:
                if state.last_window is not None and state.next_after(state.last_window) is None:
                    raise ReplayError(409, "The replay has already processed the last window; send reset to start over")
                window = state.next_after(state.last_window)
            if window in state.results:
                return state.response(window, already=True)
            state.process(window)
            return state.response(window, already=False)
