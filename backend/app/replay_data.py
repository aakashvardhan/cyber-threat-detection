"""Test traffic replayed window by window.

Accepts Sai's processed test edges (raw, pre-log, with IPs) or the Oct 6 demo
split. Rows are sorted by (window_start, src, dst) so event IDs stay stable.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

from app.timeutil import to_naive_utc

TRAFFIC_COLUMNS = [
    "connection_count", "total_duration", "maximum_duration", "total_orig_bytes", "total_resp_bytes",
    "total_orig_packets", "total_resp_packets", "tcp_count", "udp_count", "icmp_count",
]
INT_COLUMNS = {"connection_count", "total_orig_bytes", "total_resp_bytes", "total_orig_packets",
               "total_resp_packets", "tcp_count", "udp_count", "icmp_count"}


def _as_dict(value) -> dict | None:
    if value is None or (isinstance(value, float) and np.isnan(value)):
        return None
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip().startswith("{"):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return None
    return None


def _clean(value):
    if value is None:
        return None
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating, float)):
        return None if np.isnan(value) else float(value)
    return value


class ReplayData:
    def __init__(self, frame: pd.DataFrame, source: str):
        frame = frame.copy()
        frame["window_start"] = pd.to_datetime(frame["window_start"]).map(to_naive_utc)
        frame = frame.sort_values(["window_start", "src_ip_zeek", "dest_ip_zeek"], kind="mergesort").reset_index(drop=True)
        frame["event_id"] = [f"uwf-test-{i}" for i in range(len(frame))]
        self.frame = frame
        self.source = source
        self.windows: list[pd.Timestamp] = list(pd.Index(frame["window_start"].unique()).sort_values())
        self.window_position = {w: i for i, w in enumerate(self.windows)}
        # first recorded window of each UTC day: the test split has gaps, so a day may not start at 00:00
        self.day_starts: list[pd.Timestamp] = list(pd.Series(self.windows).groupby(
            pd.Series(self.windows).dt.normalize()).min()) if self.windows else []
        self._rows = frame.groupby("window_start").indices

    @classmethod
    def load(cls, path: Path | None) -> "ReplayData":
        if path is None or not Path(path).exists():
            raise FileNotFoundError(
                "No replay data found. Set REPLAY_FILE or put Sai's test_edges.parquet in DATA_DIR.")
        frame = pd.read_parquet(path)
        missing = {"window_start", "src_ip_zeek", "dest_ip_zeek"} - set(frame.columns)
        if missing:
            raise ValueError(f"{path} is missing columns {sorted(missing)}")
        return cls(frame, source=str(path))

    def __len__(self) -> int:
        return len(self.windows)

    def rows(self, window: pd.Timestamp) -> pd.DataFrame:
        return self.frame.iloc[self._rows[window]]

    def resolve(self, window_start) -> pd.Timestamp | None:
        ts = to_naive_utc(window_start)
        return ts if ts in self.window_position else None

    # ----- fields the API returns for one edge -----
    @staticmethod
    def service(row: pd.Series) -> str | None:
        for column in ("most_common_service", "dominant_zeek_service"):
            value = row.get(column)
            if isinstance(value, str) and value and value != "unknown":
                return value
        return None

    @staticmethod
    def port(row: pd.Series) -> int | None:
        for column in ("most_common_destination_port", "dominant_destination_port"):
            value = _clean(row.get(column))
            if value is not None:
                return int(value)
        return None

    def traffic_features(self, row: pd.Series) -> dict:
        features = {}
        for column in TRAFFIC_COLUMNS:
            value = _clean(row.get(column))
            if value is not None:
                features[column] = int(round(value)) if column in INT_COLUMNS else value
        features["dominant_destination_port"] = self.port(row)
        features["destination_port_group"] = _clean(row.get("destination_port_group"))
        features["dominant_zeek_service"] = self.service(row)
        for column in ("service_counts", "conn_state_counts", "conn_state_ratios"):
            parsed = _as_dict(row.get(column))
            if parsed is not None:
                features[column] = parsed
        state = row.get("most_common_connection_state")
        if "conn_state_counts" not in features and isinstance(state, str) and state:
            features["most_common_connection_state"] = state
        return features
