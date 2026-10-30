"""The 5-minute window graph around an incident's source, for the graph view.

Nodes are IPs, edges are the window's aggregated connections (one per source/destination pair), with the
detector's attack probability. The "two-hop" part is what a 2-layer GraphSAGE uses for the source's edges:
every edge that touches the source or one of its targets.
"""
from __future__ import annotations

import math
import re

import pandas as pd

from app.incidents import Incident, ReplayState
from app.timeutil import iso

INTERNAL_IP = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|143\.88\.)")
OUTCOMES = {
    "no_reply": {"S0", "SH", "SHR", "OTH"},
    "refused": {"REJ", "RSTO", "RSTR", "RSTOS0", "RSTRH"},
    "completed": {"SF", "S1", "S2", "S3"},
}
MAX_EDGES = 400


def _num(row: pd.Series, column: str) -> float:
    value = row.get(column)
    try:
        value = float(value)
    except (TypeError, ValueError):
        return 0.0
    return 0.0 if math.isnan(value) else value


def _outcome(state) -> str:
    for name, states in OUTCOMES.items():
        if state in states:
            return name
    return "unknown"


def window_graph(state: ReplayState, incident: Incident, window: pd.Timestamp, threshold: float) -> dict:
    data = state.data
    rows = data.rows(window)
    result = state.results.get(window)
    probs = result.probabilities if result is not None and result.probabilities is not None else [None] * len(rows)
    source = incident.source_ip
    src_col, dst_col = rows["src_ip_zeek"].astype(str), rows["dest_ip_zeek"].astype(str)
    targets = set(dst_col[src_col == source])
    hop1 = targets | {source}

    edges = []
    for (_, row), p in zip(rows.iterrows(), probs):
        s, d = str(row["src_ip_zeek"]), str(row["dest_ip_zeek"])
        conn_state = row.get("most_common_connection_state")
        conn_state = conn_state if isinstance(conn_state, str) and conn_state else None
        edges.append({
            "source_ip": s, "destination_ip": d,
            "attack_probability": None if p is None else round(float(p), 4),
            "flagged": p is not None and float(p) >= threshold,
            "connection_count": int(_num(row, "connection_count")),
            "service": data.service(row), "port": data.port(row),
            "connection_state": conn_state, "outcome": _outcome(conn_state),
            "orig_bytes": _num(row, "total_orig_bytes"), "resp_bytes": _num(row, "total_resp_bytes"),
            "orig_packets": int(_num(row, "total_orig_packets")), "resp_packets": int(_num(row, "total_resp_packets")),
            "in_two_hop": s in hop1 or d in hop1,
        })
    truncated = len(edges) > MAX_EDGES
    if truncated:   # keep the two-hop part, then the most suspicious of the rest
        near = [e for e in edges if e["in_two_hop"]]
        rest = sorted((e for e in edges if not e["in_two_hop"]), key=lambda e: -(e["attack_probability"] or 0))
        edges = near + rest[: max(0, MAX_EDGES - len(near))]

    two_hop_ips = {ip for e in edges if e["in_two_hop"] for ip in (e["source_ip"], e["destination_ip"])}
    ips = sorted({ip for e in edges for ip in (e["source_ip"], e["destination_ip"])})

    def role(ip: str) -> str:
        if ip == source:
            return "source"
        if ip in targets:
            return "target"
        return "second_hop" if ip in two_hop_ips else "other"

    return {
        "incident_id": incident.incident_id,
        "window_start": iso(window),
        "windows": [iso(w) for w in sorted({e.window_start for e in incident.edges})],
        "threshold": threshold,
        "source_ip": source,
        "window_edge_count": len(rows),
        "truncated": truncated,
        "nodes": [{"ip": ip, "role": role(ip), "internal": bool(INTERNAL_IP.match(ip))} for ip in ips],
        "edges": edges,
    }
