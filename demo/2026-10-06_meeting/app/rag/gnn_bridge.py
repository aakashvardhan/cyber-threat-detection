"""Convert GNN inference JSON into retrieve() events (from rag.ipynb)."""
from __future__ import annotations

import re
from typing import Any

from app.rag.paths import HOST_ONLY

INTERNAL_IP = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|143\.88\.)")


def _kind(ip: str | None) -> str:
    return "internal host" if INTERNAL_IP.match(ip or "") else "external host"


def gnn_output_to_events(
    out: dict[str, Any],
    window_min: int = 5,
    margin: float = 0.05,
    max_k: int = 2,
) -> list[dict[str, Any]]:
    """GNN inference JSON -> retrieve() events."""
    det = out["gnn_detection"]
    if det["binary_prediction"]["label"] != "attack":
        return []

    ev = out["event"]
    features = out["event"]["traffic_features"]
    protos = {
        "tcp": features.get("tcp_count", 0) or 0,
        "udp": features.get("udp_count", 0) or 0,
        "icmp": features.get("icmp_count", 0) or 0,
    }
    proto = max(protos, key=protos.get) if any(protos.values()) else "unknown"
    n = int(features.get("connection_count") or 0)
    behavior = (
        f"{_kind(ev.get('source_ip'))} made {n:,} {proto.upper()} "
        f"connection{'s' if n != 1 else ''} to one {_kind(ev.get('destination_ip'))} "
        f"within {window_min} minutes; "
        f"{float(features.get('total_orig_bytes') or 0):,.0f} bytes sent and "
        f"{float(features.get('total_resp_bytes') or 0):,.0f} bytes received "
        f"({float(features.get('total_orig_packets') or 0):,.0f}/"
        f"{float(features.get('total_resp_packets') or 0):,.0f} packets), "
        f"total duration {float(features.get('total_duration') or 0):.2f}s"
    )
    conn_ratios = features.get("conn_state_ratios") or {}
    if conn_ratios:
        fail = sum(
            float(conn_ratios.get(k, 0) or 0)
            for k in ("S0", "REJ", "RSTO", "RSTR", "RSTOS0", "RSTRH")
        )
        behavior += (
            f"; {fail:.0%} failed or rejected, "
            f"{float(conn_ratios.get('SF', 0) or 0):.0%} completed normally"
        )

    service = features.get("dominant_zeek_service") or "unknown"
    port = (
        features.get("destination_port_group")
        or features.get("dominant_destination_port")
        or "unknown"
    )

    ranked = sorted(det.get("mitre_candidates") or [], key=lambda c: -float(c["confidence"]))
    cands = [c for c in ranked if c["technique_id"].split(".")[0] not in HOST_ONLY] or ranked[:1]
    if not cands:
        return []
    top = float(cands[0]["confidence"])
    kept = [c for c in cands if top - float(c["confidence"]) <= margin][:max_k]
    tactic = (det.get("tactic_prediction") or {}).get("label")

    return [
        {
            "technique_id": c["technique_id"],
            "technique_confidence": float(c["confidence"]),
            "tactic": None,
            "service": service,
            "port": str(port),
            "protocol": proto,
            "behavior": behavior,
            "src_ip": ev.get("source_ip"),
            "dst_ip": ev.get("destination_ip"),
            "event_id": out.get("event_id"),
            "gnn_tactic": tactic,
        }
        for c in kept
    ]
