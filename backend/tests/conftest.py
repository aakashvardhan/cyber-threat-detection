import json
import sys
from pathlib import Path

import pandas as pd
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402

API_KEY = "test-key"
ATTACKER = "143.88.6.11"
START = pd.Timestamp("2025-05-30 16:00:00")


def window(i: int) -> pd.Timestamp:
    return START + pd.Timedelta(minutes=5 * i)


def make_edges() -> pd.DataFrame:
    """12 windows of normal traffic; the attacker scans port 80 in windows 2-4 and again in window 11."""
    rows = []
    for w in range(12):
        for h in range(4):
            rows.append(dict(window_start=window(w), src_ip_zeek=f"143.88.1.{10 + h}", dest_ip_zeek="143.88.255.10",
                             connection_count=2, total_duration=0.4, average_duration=0.2, maximum_duration=0.3,
                             total_orig_bytes=900.0, total_resp_bytes=1200.0, total_orig_packets=6, total_resp_packets=6,
                             total_orig_ip_bytes=1100, total_resp_ip_bytes=1400, total_missed_bytes=0,
                             unique_destination_ports=1, most_common_destination_port=53, tcp_count=0, udp_count=2,
                             icmp_count=0, most_common_service="dns", most_common_connection_state="SF",
                             binary_target=0))
        if w in (2, 3, 4, 11):
            for t in range(6):
                rows.append(dict(window_start=window(w), src_ip_zeek=ATTACKER, dest_ip_zeek=f"143.88.5.{20 + t}",
                                 connection_count=30, total_duration=1.5, average_duration=0.05, maximum_duration=0.1,
                                 total_orig_bytes=600.0, total_resp_bytes=0.0, total_orig_packets=60, total_resp_packets=30,
                                 total_orig_ip_bytes=2400, total_resp_ip_bytes=1200, total_missed_bytes=0,
                                 unique_destination_ports=1, most_common_destination_port=80, tcp_count=30, udp_count=0,
                                 icmp_count=0, most_common_service="http", most_common_connection_state="REJ",
                                 binary_target=1))
    return pd.DataFrame(rows)


def make_predictions(edges: pd.DataFrame) -> pd.DataFrame:
    attack = edges["src_ip_zeek"] == ATTACKER
    return pd.DataFrame({
        "window_start": edges["window_start"], "src_ip_zeek": edges["src_ip_zeek"], "dest_ip_zeek": edges["dest_ip_zeek"],
        "attack_probability": attack.map({True: 0.94, False: 0.03}),
        "technique_candidates": [json.dumps([{"technique_id": "T1190", "confidence": 0.72},
                                             {"technique_id": "T1595", "confidence": 0.41}]) if a else "[]" for a in attack],
        "tactic": attack.map({True: "Initial Access", False: None}),
        "tactic_confidence": attack.map({True: 0.81, False: None}),
        "severity": attack.map({True: "high", False: None}),
    })


def make_knowledge(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    pd.DataFrame([
        dict(technique_id="T1190", name="Exploit Public-Facing Application", is_subtechnique=False, parent_id="T1190",
             tactic_ids="TA0001", tactics="Initial Access", platforms="Linux",
             description="Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network.(Citation: X)",
             detection="", url="https://attack.mitre.org/techniques/T1190", mitigations=""),
        dict(technique_id="T1595", name="Active Scanning", is_subtechnique=False, parent_id="T1595", tactic_ids="TA0043",
             tactics="Reconnaissance", platforms="PRE", description="Adversaries may execute active reconnaissance scans.",
             detection="", url="https://attack.mitre.org/techniques/T1595", mitigations=""),
        dict(technique_id="T1548", name="Abuse Elevation Control Mechanism", is_subtechnique=False, parent_id="T1548",
             tactic_ids="TA0004", tactics="Privilege Escalation", platforms="Linux",
             description="Adversaries may circumvent mechanisms designed to control elevated privileges.", detection="",
             url="https://attack.mitre.org/techniques/T1548", mitigations=""),
        dict(technique_id="T1564", name="Hide Artifacts", is_subtechnique=False, parent_id="T1564", tactic_ids="TA0005",
             tactics="Stealth", platforms="Linux", description="Adversaries may attempt to hide artifacts.", detection="",
             url="https://attack.mitre.org/techniques/T1564", mitigations=""),
    ]).to_csv(directory / "mitre_lookup.csv", index=False)
    pd.DataFrame([
        dict(technique_id="T1190", mitigation_id="M1050", mitigation_name="Exploit Protection", how="..."),
        dict(technique_id="T1190", mitigation_id="M1030", mitigation_name="Network Segmentation", how="..."),
    ]).to_csv(directory / "mitre_mitigations.csv", index=False)
    chunks = [
        {"id": "proc-1", "text": "APT group exploited a public-facing web application over http port 80 to gain access.",
         "metadata": {"technique_id": "T1190", "technique_ids": ["T1190"], "source_name": "Operation Web", "source_attack_id": "C0001"}},
        {"id": "proc-2", "text": "Threat actor scanned http services across many targets.",
         "metadata": {"technique_id": "T1595", "technique_ids": ["T1595"], "source_name": "Scanner Group", "source_attack_id": "G0001"}},
        {"id": "proc-3", "text": "Actor hid files in hidden directories to evade defenders.",
         "metadata": {"technique_id": "T1564", "technique_ids": ["T1564"], "source_name": "Hider", "source_attack_id": "G0002"}},
    ]
    with (directory / "procedure_chunks.jsonl").open("w") as handle:
        for chunk in chunks:
            handle.write(json.dumps(chunk) + "\n")


@pytest.fixture
def paths(tmp_path):
    edges = make_edges()
    edges.to_parquet(tmp_path / "test_edges.parquet", index=False)
    make_predictions(edges).to_parquet(tmp_path / "primary_predictions.parquet", index=False)
    make_knowledge(tmp_path / "knowledge")
    return tmp_path


@pytest.fixture
def make_settings(paths):
    def factory(**overrides):
        base = dict(api_key=API_KEY, data_dir=paths, replay_file=paths / "test_edges.parquet",
                    primary_model="precomputed", primary_predictions=paths / "primary_predictions.parquet",
                    threshold=0.5, knowledge_dir=paths / "knowledge",
                    metrics_file=Path(__file__).resolve().parents[1] / "app" / "data" / "metrics.default.json",
                    llm_provider="none")
        base.update(overrides)
        return Settings(**base)
    return factory


@pytest.fixture
def client(make_settings):
    app = create_app(make_settings())
    with TestClient(app, headers={"X-API-Key": API_KEY}) as test_client:
        yield test_client


def wait_ready(client, incident_id, timeout=10):
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        body = client.get(f"/incidents/{incident_id}").json()
        if body["explanation"]["status"] != "generating":
            return body
        time.sleep(0.05)
    raise AssertionError("explanation did not finish")
