"""Primary model behind POST /detect.

- GraphSAGEDetector: Sai's 3-head GraphSAGE (binary, tactic, MITRE), with her preprocessing
  rebuilt per window from preprocessing_objects.joblib.
- PrecomputedDetector: per-edge predictions exported from any model (e.g. the decision model,
  model_5, which also supplies severity).
- HeuristicDetector: label-free stand-in so the API works before the artifacts arrive.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from app.config import Settings
from app.replay_data import ReplayData
from app.timeutil import to_naive_utc

log = logging.getLogger(__name__)

# Sai's feature lists (Data-Prep-Final.ipynb, sections 6-8)
NUMERIC_EDGE_FEATURES = [
    "connection_count", "total_duration", "average_duration", "maximum_duration", "total_orig_bytes",
    "total_resp_bytes", "total_orig_packets", "total_resp_packets", "total_orig_ip_bytes",
    "total_resp_ip_bytes", "total_missed_bytes", "unique_destination_ports",
    "most_common_destination_port", "tcp_count", "udp_count", "icmp_count",
]
LOG_EDGE_FEATURES = [c for c in NUMERIC_EDGE_FEATURES if c != "most_common_destination_port"]
CATEGORICAL_EDGE_FEATURES = ["most_common_service", "most_common_connection_state"]
NODE_FEATURES = [
    "outgoing_edge_count", "outgoing_connection_count", "unique_destinations", "outgoing_duration",
    "outgoing_orig_bytes", "outgoing_orig_packets", "outgoing_orig_ip_bytes", "outgoing_missed_bytes",
    "outgoing_tcp_count", "outgoing_udp_count", "outgoing_icmp_count", "incoming_edge_count",
    "incoming_connection_count", "unique_sources", "incoming_duration", "incoming_resp_bytes",
    "incoming_resp_packets", "incoming_resp_ip_bytes", "incoming_missed_bytes", "incoming_tcp_count",
    "incoming_udp_count", "incoming_icmp_count",
]


@dataclass
class Prediction:
    """Per-edge outputs for one window, in the window's row order."""
    attack_probability: np.ndarray
    tactic_classes: list[str] = field(default_factory=list)
    tactic_probs: np.ndarray | None = None
    technique_classes: list[str] = field(default_factory=list)
    technique_probs: np.ndarray | None = None
    severity: list[str | None] | None = None


class Detector:
    name = "detector"
    threshold = 0.5

    def predict(self, rows: pd.DataFrame) -> Prediction:
        raise NotImplementedError


# ---------------------------------------------------------------- GraphSAGE (Sai)
def build_node_features(edges: pd.DataFrame) -> pd.DataFrame:
    """Sai's build_node_features: per (window, ip) behaviour as source and as destination."""
    outgoing = (edges.groupby(["window_start", "src_ip_zeek"]).agg(
        outgoing_edge_count=("dest_ip_zeek", "size"),
        outgoing_connection_count=("connection_count", "sum"),
        unique_destinations=("dest_ip_zeek", "nunique"),
        outgoing_duration=("total_duration", "sum"),
        outgoing_orig_bytes=("total_orig_bytes", "sum"),
        outgoing_orig_packets=("total_orig_packets", "sum"),
        outgoing_orig_ip_bytes=("total_orig_ip_bytes", "sum"),
        outgoing_missed_bytes=("total_missed_bytes", "sum"),
        outgoing_tcp_count=("tcp_count", "sum"),
        outgoing_udp_count=("udp_count", "sum"),
        outgoing_icmp_count=("icmp_count", "sum"),
    ).reset_index().rename(columns={"src_ip_zeek": "ip"}))
    incoming = (edges.groupby(["window_start", "dest_ip_zeek"]).agg(
        incoming_edge_count=("src_ip_zeek", "size"),
        incoming_connection_count=("connection_count", "sum"),
        unique_sources=("src_ip_zeek", "nunique"),
        incoming_duration=("total_duration", "sum"),
        incoming_resp_bytes=("total_resp_bytes", "sum"),
        incoming_resp_packets=("total_resp_packets", "sum"),
        incoming_resp_ip_bytes=("total_resp_ip_bytes", "sum"),
        incoming_missed_bytes=("total_missed_bytes", "sum"),
        incoming_tcp_count=("tcp_count", "sum"),
        incoming_udp_count=("udp_count", "sum"),
        incoming_icmp_count=("icmp_count", "sum"),
    ).reset_index().rename(columns={"dest_ip_zeek": "ip"}))
    nodes = outgoing.merge(incoming, on=["window_start", "ip"], how="outer")
    numeric = nodes.select_dtypes(include="number").columns
    nodes[numeric] = nodes[numeric].fillna(0)
    return nodes


def _graphsage_class():
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    from torch_geometric.nn import SAGEConv

    class GraphSAGEEdgeClassifier(nn.Module):
        """Sai's model (Threat Detection Model Training Final.ipynb, section 2)."""

        def __init__(self, node_input_dim, edge_input_dim, hidden_dim, tactic_dim, mitre_dim, dropout=0.3):
            super().__init__()
            self.conv1 = SAGEConv(node_input_dim, hidden_dim)
            self.conv2 = SAGEConv(hidden_dim, hidden_dim)
            self.dropout = dropout
            size = hidden_dim * 2 + edge_input_dim
            head = lambda out: nn.Sequential(nn.Linear(size, hidden_dim), nn.ReLU(), nn.Dropout(dropout), nn.Linear(hidden_dim, out))
            self.binary_head = head(1)
            self.tactic_head = head(tactic_dim)
            self.mitre_head = head(mitre_dim)

        def forward(self, data):
            x = F.relu(self.conv1(data.x, data.edge_index))
            x = F.dropout(x, p=self.dropout, training=self.training)
            x = F.relu(self.conv2(x, data.edge_index))
            source, destination = data.edge_index
            edge = torch.cat([x[source], x[destination], data.edge_attr], dim=1)
            return self.binary_head(edge).squeeze(1), self.tactic_head(edge), self.mitre_head(edge)

    return GraphSAGEEdgeClassifier


class GraphSAGEDetector(Detector):
    name = "graphsage"

    def __init__(self, checkpoint_path, preprocessing_path):
        import joblib
        import torch

        self.torch = torch
        objects = joblib.load(preprocessing_path)
        self.edge_scaler = objects["edge_scaler"]
        self.node_scaler = objects["node_scaler"]
        self.category_encoder = objects["edge_category_encoder"]
        self.tactic_classes = [str(c) for c in objects["tactic_encoder"].classes_]
        self.technique_classes = [str(c) for c in objects["mitre_encoder"].classes_]

        checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=False)
        self.model = _graphsage_class()(**checkpoint["model_config"])
        self.model.load_state_dict(checkpoint["model_state_dict"])
        self.model.eval()
        self.threshold = float(checkpoint.get("threshold", 0.5))

    @staticmethod
    def required_columns() -> set[str]:
        return set(NUMERIC_EDGE_FEATURES) | set(CATEGORICAL_EDGE_FEATURES) | {
            "total_duration", "total_orig_packets", "total_missed_bytes"}

    def predict(self, rows: pd.DataFrame) -> Prediction:
        from torch_geometric.data import Data

        torch = self.torch
        edges = rows.copy()
        for column in CATEGORICAL_EDGE_FEATURES:
            edges[column] = edges[column].fillna("unknown")

        numeric = edges[NUMERIC_EDGE_FEATURES].astype("float64")
        numeric[LOG_EDGE_FEATURES] = np.log1p(numeric[LOG_EDGE_FEATURES].clip(lower=0))
        edge_x = np.hstack([
            self.edge_scaler.transform(numeric).astype(np.float32),
            self.category_encoder.transform(edges[CATEGORICAL_EDGE_FEATURES]).astype(np.float32),
        ])

        nodes = build_node_features(edges)
        node_values = np.log1p(nodes[NODE_FEATURES].astype("float64").clip(lower=0))
        node_x = self.node_scaler.transform(node_values).astype(np.float32)
        node_id = {ip: i for i, ip in enumerate(nodes["ip"])}
        edge_index = torch.tensor([[node_id[ip] for ip in edges["src_ip_zeek"]],
                                   [node_id[ip] for ip in edges["dest_ip_zeek"]]], dtype=torch.long)

        data = Data(x=torch.tensor(node_x), edge_index=edge_index, edge_attr=torch.tensor(edge_x))
        with torch.no_grad():
            binary, tactic, technique = self.model(data)
        return Prediction(
            attack_probability=torch.sigmoid(binary).numpy(),
            tactic_classes=self.tactic_classes,
            tactic_probs=torch.sigmoid(tactic).numpy(),
            technique_classes=self.technique_classes,
            technique_probs=torch.sigmoid(technique).numpy(),
        )


# ---------------------------------------------------------------- precomputed
class PrecomputedDetector(Detector):
    """Reads per-edge predictions.

    Columns: window_start, src_ip_zeek, dest_ip_zeek, attack_probability; optional
    technique_candidates (JSON list of {technique_id, confidence}) or technique_id +
    technique_confidence; tactic + tactic_confidence; severity; threshold.
    """
    name = "precomputed"

    def __init__(self, path, threshold: float | None = None):
        frame = pd.read_parquet(path)
        frame["window_start"] = pd.to_datetime(frame["window_start"]).map(to_naive_utc)
        self.by_key = frame.set_index(["window_start", "src_ip_zeek", "dest_ip_zeek"])
        if threshold is not None:
            self.threshold = threshold
        elif "threshold" in frame.columns:
            self.threshold = float(frame["threshold"].iloc[0])

        techniques, tactics = set(), set()
        for _, row in frame.iterrows():
            techniques.update(c["technique_id"] for c in self._candidates(row))
            if isinstance(row.get("tactic"), str):
                tactics.add(row["tactic"])
        self.technique_classes = sorted(techniques)
        self.tactic_classes = sorted(tactics)

    @staticmethod
    def _candidates(row) -> list[dict]:
        raw = row.get("technique_candidates")
        if isinstance(raw, str):
            raw = json.loads(raw)
        if isinstance(raw, (list, np.ndarray)) and len(raw):
            return [dict(c) for c in raw]
        if isinstance(row.get("technique_id"), str):
            return [{"technique_id": row["technique_id"], "confidence": float(row.get("technique_confidence", 1.0) or 1.0)}]
        return []

    def predict(self, rows: pd.DataFrame) -> Prediction:
        n = len(rows)
        attack = np.zeros(n)
        technique = np.zeros((n, len(self.technique_classes)))
        tactic = np.zeros((n, len(self.tactic_classes)))
        severity: list[str | None] = [None] * n
        t_index = {t: i for i, t in enumerate(self.technique_classes)}
        a_index = {t: i for i, t in enumerate(self.tactic_classes)}
        for i, (_, edge) in enumerate(rows.iterrows()):
            key = (edge["window_start"], edge["src_ip_zeek"], edge["dest_ip_zeek"])
            if key not in self.by_key.index:
                continue
            row = self.by_key.loc[key]
            row = row.iloc[0] if isinstance(row, pd.DataFrame) else row
            attack[i] = float(row["attack_probability"])
            for c in self._candidates(row):
                technique[i, t_index[c["technique_id"]]] = float(c["confidence"])
            if isinstance(row.get("tactic"), str):
                tactic[i, a_index[row["tactic"]]] = float(row.get("tactic_confidence", 1.0) or 1.0)
            if isinstance(row.get("severity"), str):
                severity[i] = row["severity"]
        return Prediction(attack, self.tactic_classes, tactic, self.technique_classes, technique,
                          severity if any(severity) else None)


# ---------------------------------------------------------------- fallback
class HeuristicDetector(Detector):
    """Label-free placeholder: scores scan- and brute-force-like traffic shapes.

    Only for development before the trained model is available; /incidents reports it as
    'heuristic-fallback' so nobody mistakes it for the real model.
    """
    name = "heuristic-fallback"
    TECHNIQUES = ["T1046", "T1110", "T1190", "T1595"]
    TACTICS = ["Credential Access", "Discovery", "Initial Access", "Reconnaissance"]

    def predict(self, rows: pd.DataFrame) -> Prediction:
        count = rows.get("connection_count", pd.Series(1, index=rows.index)).astype(float).clip(lower=1)
        orig = rows.get("total_orig_bytes", pd.Series(0, index=rows.index)).astype(float)
        resp = rows.get("total_resp_bytes", pd.Series(0, index=rows.index)).astype(float)
        bytes_per_conn = (orig + resp) / count
        fan_out = rows.groupby("src_ip_zeek")["dest_ip_zeek"].transform("nunique").astype(float)
        z = 0.9 * np.log1p(count) + 0.6 * np.log1p(fan_out) - 0.35 * np.log1p(bytes_per_conn) - 2.6
        attack = 1 / (1 + np.exp(-z.to_numpy()))

        port = rows.get("most_common_destination_port", rows.get("dominant_destination_port", pd.Series(np.nan, index=rows.index)))
        port = pd.to_numeric(port, errors="coerce").to_numpy()
        technique = np.full((len(rows), 4), 0.05)
        tactic = np.full((len(rows), 4), 0.05)
        for i in range(len(rows)):
            if port[i] in (22, 3389, 445):
                j = 1          # brute force -> Credential Access
            elif port[i] in (80, 443, 8080):
                j = 2          # exploit public-facing app -> Initial Access
            elif fan_out.iloc[i] >= 5:
                j = 3          # active scanning -> Reconnaissance
            else:
                j = 0          # network service discovery -> Discovery
            technique[i, j] = 0.6
            tactic[i, [1, 0, 2, 3][j]] = 0.6
        return Prediction(attack, self.TACTICS, tactic, self.TECHNIQUES, technique)


def load_detector(settings: Settings, replay: ReplayData) -> Detector:
    choice = settings.primary_model
    errors = []

    def try_precomputed():
        if settings.primary_predictions and settings.primary_predictions.exists():
            return PrecomputedDetector(settings.primary_predictions, settings.threshold)
        errors.append("precomputed: no PRIMARY_PREDICTIONS file")

    def try_graphsage():
        if not (settings.model_checkpoint and settings.preprocessing_file):
            errors.append("graphsage: MODEL_CHECKPOINT or PREPROCESSING_FILE missing")
            return None
        missing = GraphSAGEDetector.required_columns() - set(replay.frame.columns)
        if missing:
            errors.append(f"graphsage: replay data lacks {sorted(missing)}")
            return None
        try:
            return GraphSAGEDetector(settings.model_checkpoint, settings.preprocessing_file)
        except Exception as exc:  # noqa: BLE001 - report and fall back
            errors.append(f"graphsage: {exc}")
            return None

    order = {"precomputed": [try_precomputed], "graphsage": [try_graphsage],
             "heuristic": [], "auto": [try_precomputed, try_graphsage]}.get(choice)
    if order is None:
        raise ValueError(f"Unknown PRIMARY_MODEL {choice!r}")
    for attempt in order:
        detector = attempt()
        if detector is not None:
            break
    else:
        if choice not in ("heuristic", "auto"):
            raise RuntimeError(f"PRIMARY_MODEL={choice} could not be loaded: {errors}")
        detector = HeuristicDetector()
        log.warning("Using heuristic fallback detector (%s)", "; ".join(errors) or "requested")
    if settings.threshold is not None:
        detector.threshold = settings.threshold
    return detector
