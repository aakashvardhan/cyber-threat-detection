"""Event record layout and reply parsing for the Gemma 4 demo.

Prompt wording and few-shot examples are not kept in this repository (see prompts.py).
"""
import json
import re

import pandas as pd

_MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def event_record(row, row_id, split="test", include_ips=True):
    """Build the event JSON record for one edge row (pandas Series / dict)."""
    def f(key):
        return float(row[key])

    event = {"window_start": pd.Timestamp(row["window_start"]).strftime("%Y-%m-%dT%H:%M:%S")}
    if include_ips:
        event["source_ip"] = row["src_ip_zeek"]
        event["destination_ip"] = row["dest_ip_zeek"]
    event["traffic_features"] = {
        "connection_count": int(row["connection_count"]),
        "total_duration": f("total_duration"),
        "maximum_duration": f("maximum_duration"),
        "total_orig_bytes": f("total_orig_bytes"),
        "total_resp_bytes": f("total_resp_bytes"),
        "total_orig_packets": f("total_orig_packets"),
        "total_resp_packets": f("total_resp_packets"),
        "tcp_count": f("tcp_count"),
        "udp_count": f("udp_count"),
        "icmp_count": f("icmp_count"),
        "dominant_destination_port": None,
        "destination_port_group": None,
        "dominant_zeek_service": None,
        "service_counts": {},
        "conn_state_counts": {},
        "conn_state_ratios": {},
    }
    return {"event_id": f"uwf-{split}-{int(row_id)}", "row_id": int(row_id), "event": event}


def serialize_event_json(row, row_id, split="test", include_ips=True):
    return json.dumps(event_record(row, row_id, split, include_ips), indent=2)


def parse_answer(text):
    """Parse an LLM reply -> (label, mitre). label: 1 attack, 0 normal, None if unparseable."""
    if not isinstance(text, str):
        return None, None
    label = mitre = None
    m = re.search(r"\{.*?\}", text, flags=re.S)
    if m:
        try:
            obj = json.loads(m.group(0))
            lab = str(obj.get("label", "")).strip().lower()
            if lab in ("attack", "normal"):
                label = 1 if lab == "attack" else 0
            code = obj.get("mitre")
            if isinstance(code, str):
                found = _MITRE_RE.search(code.upper())
                mitre = found.group(0) if found else None
        except (json.JSONDecodeError, AttributeError):
            pass
    if label is None:
        low = text.lower()
        if re.search(r"\b(not an attack|normal|benign)\b", low):
            label = 0
        elif re.search(r"\battack\b", low):
            label = 1
    if mitre is None:
        found = _MITRE_RE.search(text.upper())
        mitre = found.group(0) if found else None
    if label == 0:
        mitre = None
    return label, mitre
