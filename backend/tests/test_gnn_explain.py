"""GNNExplainer for the GraphSAGE detector (GET /incidents/{id}/model-explanation)."""
import time
from types import SimpleNamespace

import numpy as np
import pandas as pd
import pytest

torch = pytest.importorskip("torch")
pytest.importorskip("torch_geometric")

from app.detectors import NODE_FEATURES, NUMERIC_EDGE_FEATURES, _graphsage_class  # noqa: E402
from app.gnn_explain import ModelExplainer, explain_edge, feature_label, present  # noqa: E402
from conftest import window  # noqa: E402

EDGE_NAMES = NUMERIC_EDGE_FEATURES + ["most_common_service_http", "most_common_connection_state_S0"]


def tiny_graph(seed=0):
    torch.manual_seed(seed)
    model = _graphsage_class()(node_input_dim=len(NODE_FEATURES), edge_input_dim=len(EDGE_NAMES), hidden_dim=8,
                               tactic_dim=2, mitre_dim=3).eval()
    from torch_geometric.data import Data
    edge_index = torch.tensor([[0, 0, 0, 1, 2], [1, 2, 3, 3, 0]])
    data = Data(x=torch.randn(4, len(NODE_FEATURES)), edge_index=edge_index, edge_attr=torch.randn(5, len(EDGE_NAMES)))
    rows = pd.DataFrame({"src_ip_zeek": ["10.0.0.1", "10.0.0.1", "10.0.0.1", "10.0.0.2", "10.0.0.3"],
                         "dest_ip_zeek": ["10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.4", "10.0.0.1"],
                         "connection_count": [40, 3, 1, 2, 5], "most_common_connection_state": ["S0", "SF", "SF", "SF", "REJ"],
                         "most_common_service": ["http", None, None, "dns", None]},
                        index=[100, 101, 102, 103, 104])
    for name in NUMERIC_EDGE_FEATURES[1:]:
        rows[name] = 1.0
    return model, data, rows


def test_explain_edge_matches_the_model_and_names_features():
    model, data, rows = tiny_graph()
    raw = explain_edge(model, data, 0, EDGE_NAMES, NODE_FEATURES, epochs=5)
    with torch.no_grad():
        expected = float(torch.sigmoid(model(data)[0][0]))
    assert raw["probability"] == pytest.approx(expected, abs=1e-5)      # dropout off, masks removed
    assert len(raw["edge_mask"]) == 5 and len(raw["edge_feature_importance"]) == len(EDGE_NAMES)
    assert len(raw["node_feature_importance"]) == len(NODE_FEATURES)

    view = present(raw, rows, 0, EDGE_NAMES, NODE_FEATURES)
    assert len(view["edge_features"]) == 5 and view["edge_features"][0]["share"] == 1.0
    assert all(0 <= f["share"] <= 1 for f in view["edge_features"] + view["node_features"])
    by_name = {f["feature"]: f for f in view["edge_features"]}
    if "connection_count" in by_name:
        assert by_name["connection_count"]["value"] == 40                # the edge's own, unscaled value
    assert sum(n["is_explained_edge"] for n in view["neighbor_edges"]) <= 1
    assert view["faithfulness"]["probability_before"] == pytest.approx(expected, abs=1e-4)
    assert len(view["faithfulness"]["features_removed"]) == 5


def test_feature_labels_are_readable():
    assert feature_label("unique_destination_ports") == "Distinct destination ports"
    assert feature_label("most_common_connection_state_S0") == "Connection state = S0 (no reply)"
    assert feature_label("most_common_service_dns") == "Service = dns"


def test_model_explainer_runs_in_the_background_and_caches():
    model, data, rows = tiny_graph()
    detector = SimpleNamespace(model=model, build_graph=lambda r: data, edge_feature_names=EDGE_NAMES,
                               node_feature_names=list(NODE_FEATURES))
    when = pd.Timestamp("2024-03-19 07:10")
    replay = SimpleNamespace(rows=lambda w: rows)
    edge = lambda row, p: SimpleNamespace(row=row, attack_probability=p, event_id=f"uwf-test-{row}", window_start=when,
                                          source_ip="10.0.0.1", destination_ip="10.0.0.2")
    incident = SimpleNamespace(incident_id="INC-0001", edges=[edge(101, 0.7), edge(100, 0.9)])
    explainer = ModelExplainer(detector, replay, epochs=5)

    first = explainer.view(incident)
    assert first["status"] in ("computing", "ready") and first["edge"]["event_id"] == "uwf-test-100"   # top edge
    for _ in range(100):
        result = explainer.view(incident)
        if result["status"] != "computing":
            break
        time.sleep(0.05)
    assert result["status"] == "ready", result
    assert result["neighbor_edges"] and result["edge_features"] and "GNNExplainer" in result["method"]
    assert explainer.view(incident)["computed_at"] == result["computed_at"]          # cached

    incident.edges.append(edge(102, 0.95))                                              # a new top edge -> recompute
    assert explainer.view(incident)["edge"]["event_id"] == "uwf-test-102"


def test_endpoint_is_unavailable_for_other_detectors(client):
    client.post("/detect", json={"window_start": window(2).strftime("%Y-%m-%dT%H:%M:%SZ")})
    incidents = client.get("/incidents").json()["incidents"]
    body = client.get(f"/incidents/{incidents[0]['incident_id']}/model-explanation").json()
    assert body["status"] == "unavailable" and body["incident_id"] == incidents[0]["incident_id"]
    assert client.get("/incidents/INC-9999/model-explanation").status_code == 404
