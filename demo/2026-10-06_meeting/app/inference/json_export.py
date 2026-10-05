"""JSON export helpers from Combined_Model_Inference_v2."""
from __future__ import annotations

import ast
import json
from typing import Any

import numpy as np
import pandas as pd


def clean_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (list, tuple, set, np.ndarray)):
        return [clean_value(item) for item in value]
    if isinstance(value, dict):
        return {str(k): clean_value(v) for k, v in value.items()}
    try:
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass
    if isinstance(value, pd.Timestamp):
        return value.isoformat()
    if isinstance(value, np.generic):
        return value.item()
    return value


def parse_json_dict(value: Any) -> dict:
    if isinstance(value, dict):
        return clean_value(value)
    if value is None or (isinstance(value, float) and np.isnan(value)):
        return {}
    try:
        return clean_value(json.loads(str(value)))
    except (json.JSONDecodeError, TypeError):
        return {}


def parse_label_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set, np.ndarray)):
        return [
            str(item)
            for item in value
            if str(item).lower() not in {"none", "nan", "unknown"}
        ]
    try:
        if pd.isna(value):
            return []
    except (TypeError, ValueError):
        pass
    text = str(value).strip()
    if text.startswith("["):
        try:
            return parse_label_list(ast.literal_eval(text))
        except (ValueError, SyntaxError):
            pass
    return [] if text.lower() in {"", "none", "nan", "unknown"} else [text]


def create_gnn_json(row: dict | pd.Series, include_ground_truth: bool = False) -> dict:
    mitre_candidates = []
    for rank in range(1, 4):
        technique_id = row.get(f"mitre_top_{rank}")
        if pd.notna(technique_id):
            mitre_candidates.append(
                {
                    "rank": rank,
                    "technique_id": str(technique_id),
                    "confidence": float(row[f"mitre_top_{rank}_confidence"]),
                }
            )

    tactic_prediction = None
    if pd.notna(row.get("tactic")):
        tactic_prediction = {
            "label": str(row["tactic"]),
            "confidence": float(row["tactic_confidence"]),
            "confidence_type": "softmax",
        }

    row_id = int(row["row_id"])
    result = {
        "event_id": f"uwf-test-{row_id}",
        "row_id": row_id,
        "event": {
            "window_start": clean_value(row.get("window_start")),
            "source_ip": clean_value(row.get("src_ip_zeek")),
            "destination_ip": clean_value(row.get("dest_ip_zeek")),
            "traffic_features": {
                "connection_count": clean_value(row.get("connection_count")),
                "total_duration": clean_value(row.get("total_duration")),
                "maximum_duration": clean_value(row.get("maximum_duration")),
                "total_orig_bytes": clean_value(row.get("total_orig_bytes")),
                "total_resp_bytes": clean_value(row.get("total_resp_bytes")),
                "total_orig_packets": clean_value(row.get("total_orig_packets")),
                "total_resp_packets": clean_value(row.get("total_resp_packets")),
                "tcp_count": clean_value(row.get("tcp_count")),
                "udp_count": clean_value(row.get("udp_count")),
                "icmp_count": clean_value(row.get("icmp_count")),
                "dominant_destination_port": clean_value(row.get("dominant_destination_port")),
                "destination_port_group": clean_value(row.get("destination_port_group")),
                "dominant_zeek_service": clean_value(row.get("dominant_zeek_service")),
                "service_counts": parse_json_dict(row.get("service_counts")),
                "conn_state_counts": parse_json_dict(row.get("conn_state_counts")),
                "conn_state_ratios": parse_json_dict(row.get("conn_state_ratios")),
            },
        },
        "gnn_detection": {
            "binary_prediction": {
                "label": str(row["binary_label"]),
                "attack_probability": float(row["attack_probability"]),
                "confidence": float(row["binary_confidence"]),
                "confidence_type": "sigmoid",
            },
            "selected_mitre_id": mitre_candidates[0]["technique_id"] if mitre_candidates else None,
            "mitre_confidence_type": "independent_sigmoid",
            "mitre_candidates": mitre_candidates,
            "tactic_prediction": tactic_prediction,
        },
    }

    if include_ground_truth:
        result["ground_truth"] = {
            "label_binary": int(row["true_label_binary"]),
            "label_technique": parse_label_list(row.get("true_label_technique")),
            "label_tactic": parse_label_list(row.get("true_label_tactic")),
        }
    return result
