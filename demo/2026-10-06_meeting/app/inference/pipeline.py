"""Run combined GNN inference for a single 5-minute window."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd
import torch
from torch_geometric.loader import DataLoader

from app.config import (
    BINARY_PATH,
    MITRE_PATH,
    RAG_METADATA_PARQUET,
    TACTIC_PATH,
    TEST_EDGES_PARQUET,
    TEST_GRAPHS_PATH,
    load_binary_threshold,
)
from app.inference.json_export import create_gnn_json
from app.inference.models import BinaryGraphSAGE, EdgeLabelGraphSAGE

EVENT_COLUMNS = [
    "window_start",
    "src_ip_zeek",
    "dest_ip_zeek",
    "connection_count",
    "total_duration",
    "maximum_duration",
    "total_orig_bytes",
    "total_resp_bytes",
    "total_orig_packets",
    "total_resp_packets",
    "tcp_count",
    "udp_count",
    "icmp_count",
    "dominant_destination_port",
    "destination_port_group",
    "dominant_zeek_service",
    "service_counts",
    "conn_state_counts",
    "conn_state_ratios",
]


@dataclass
class InferenceBundle:
    window_start: pd.Timestamp
    records: list[dict[str, Any]]
    json_events: list[dict[str, Any]]


class CombinedInferenceEngine:
    """Loads models once and runs inference per 5-minute window."""

    def __init__(self) -> None:
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.binary_threshold = load_binary_threshold()
        self.test_edges = self._load_test_edges()
        self.window_to_graph = self._load_graph_index()
        self._load_models()

    def _load_test_edges(self) -> pd.DataFrame:
        edges = (
            pd.read_parquet(TEST_EDGES_PARQUET)
            .sort_values("window_start", kind="quicksort")
            .reset_index(drop=True)
        )
        edges["window_start"] = pd.to_datetime(edges["window_start"]).dt.tz_localize(None)
        if RAG_METADATA_PARQUET.exists():
            rag_metadata = pd.read_parquet(RAG_METADATA_PARQUET)
            if len(rag_metadata) > 0:
                rag_metadata["window_start"] = pd.to_datetime(
                    rag_metadata["window_start"]
                ).dt.tz_localize(None)
                enrichment_columns = [
                    "dominant_destination_port",
                    "destination_port_group",
                    "dominant_zeek_service",
                    "service_counts",
                    "conn_state_counts",
                    "conn_state_ratios",
                ]
                edges = edges.drop(
                    columns=[c for c in enrichment_columns if c in edges.columns]
                )
                edges["_row_order"] = np.arange(len(edges))
                edges = (
                    edges.merge(
                        rag_metadata,
                        on=["window_start", "src_ip_zeek", "dest_ip_zeek"],
                        how="left",
                        validate="one_to_one",
                        sort=False,
                    )
                    .sort_values("_row_order", kind="stable")
                    .drop(columns="_row_order")
                    .reset_index(drop=True)
                )
        return edges

    def _load_graph_index(self) -> dict[pd.Timestamp, Any]:
        test_graphs = torch.load(
            TEST_GRAPHS_PATH,
            map_location="cpu",
            weights_only=False,
        )
        unique_windows = self.test_edges["window_start"].drop_duplicates().tolist()
        if len(unique_windows) != len(test_graphs):
            raise ValueError(
                f"Window count ({len(unique_windows)}) != graph count ({len(test_graphs)})."
            )
        mapping = {}
        for window, graph in zip(unique_windows, test_graphs, strict=True):
            ids = graph.target_row_ids if hasattr(graph, "target_row_ids") else graph.target_row_index
            graph.rag_row_ids = ids.clone().long()
            mapping[pd.Timestamp(window)] = graph
        return mapping

    def _load_models(self) -> None:
        self.binary_model = BinaryGraphSAGE().to(self.device)
        self.binary_model.load_state_dict(
            torch.load(BINARY_PATH, map_location=self.device, weights_only=False)
        )

        self.mitre_checkpoint = torch.load(
            MITRE_PATH, map_location=self.device, weights_only=False
        )
        self.tactic_checkpoint = torch.load(
            TACTIC_PATH, map_location=self.device, weights_only=False
        )

        self.mitre_model = EdgeLabelGraphSAGE(len(self.mitre_checkpoint["classes"])).to(
            self.device
        )
        self.mitre_model.load_state_dict(self.mitre_checkpoint["model_state_dict"])

        self.tactic_model = EdgeLabelGraphSAGE(len(self.tactic_checkpoint["classes"])).to(
            self.device
        )
        self.tactic_model.load_state_dict(self.tactic_checkpoint["model_state_dict"])

        self.binary_model.eval()
        self.mitre_model.eval()
        self.tactic_model.eval()

    def available_windows(self) -> list[pd.Timestamp]:
        return sorted(self.window_to_graph.keys())

    def run_window(
        self, window_start: pd.Timestamp, include_ground_truth: bool = True
    ) -> InferenceBundle:
        key = pd.Timestamp(window_start)
        if key not in self.window_to_graph:
            raise KeyError(f"No graph for window {key.isoformat()}")

        graph = self.window_to_graph[key]
        loader = DataLoader([graph], batch_size=1, shuffle=False, num_workers=0)
        records: list[dict[str, Any]] = []

        with torch.inference_mode():
            for batch in loader:
                row_ids = batch.rag_row_ids.cpu().numpy().astype(int)
                batch = batch.to(self.device)

                binary_probabilities = torch.sigmoid(self.binary_model(batch)).cpu().numpy()
                mitre_probabilities = torch.sigmoid(self.mitre_model(batch)).cpu().numpy()
                tactic_probabilities = torch.softmax(self.tactic_model(batch), dim=1).cpu().numpy()

                for position, row_id in enumerate(row_ids):
                    attack_probability = float(binary_probabilities[position])
                    is_attack = attack_probability >= self.binary_threshold
                    source = self.test_edges.iloc[int(row_id)]

                    record: dict[str, Any] = {
                        "row_id": int(row_id),
                        "binary_label": "attack" if is_attack else "normal",
                        "attack_probability": attack_probability,
                        "binary_confidence": attack_probability
                        if is_attack
                        else 1.0 - attack_probability,
                    }
                    for column in EVENT_COLUMNS:
                        record[column] = source.get(column)

                    if is_attack:
                        technique_ids = np.argsort(-mitre_probabilities[position])[:3]
                        for rank, technique_id in enumerate(technique_ids, start=1):
                            record[f"mitre_top_{rank}"] = self.mitre_checkpoint["classes"][
                                technique_id
                            ]
                            record[f"mitre_top_{rank}_confidence"] = float(
                                mitre_probabilities[position, technique_id]
                            )
                        tactic_id = int(np.argmax(tactic_probabilities[position]))
                        record["tactic"] = self.tactic_checkpoint["classes"][tactic_id]
                        record["tactic_confidence"] = float(
                            tactic_probabilities[position, tactic_id]
                        )
                    else:
                        for rank in range(1, 4):
                            record[f"mitre_top_{rank}"] = None
                            record[f"mitre_top_{rank}_confidence"] = None
                        record["tactic"] = None
                        record["tactic_confidence"] = None

                    if include_ground_truth:
                        record["true_label_binary"] = int(source["binary_target"])
                        record["true_label_technique"] = source.get("mitre_targets")
                        record["true_label_tactic"] = source.get("tactic_targets")

                    records.append(record)

        json_events = [
            create_gnn_json(row, include_ground_truth=include_ground_truth) for row in records
        ]
        return InferenceBundle(window_start=key, records=records, json_events=json_events)
