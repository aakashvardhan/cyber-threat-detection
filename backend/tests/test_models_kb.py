"""Live-model switching (GET /models, POST /models/active) and knowledge-base browsing (GET /knowledge-base)."""
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from conftest import API_KEY


def test_models_lists_the_live_model_and_unavailable_graph_models(client):
    body = client.get("/models").json()
    assert body["active"] == "precomputed"
    by_id = {m["id"]: m for m in body["models"]}
    assert by_id["precomputed"]["active"] and by_id["precomputed"]["live"]
    assert by_id["graphsage"]["available"] is False and "MODEL_CHECKPOINT" in by_id["graphsage"]["note"]
    assert by_id["hgt"]["available"] is False


def test_switching_rejects_offline_and_missing_models(client):
    assert client.post("/models/active", json={"model": "mistral"}).status_code == 400
    response = client.post("/models/active", json={"model": "hgt"})
    assert response.status_code == 409
    assert client.get("/models").json()["active"] == "precomputed"     # unchanged


def test_switching_restarts_the_replay_with_the_new_model(make_settings, tmp_path):
    torch = pytest.importorskip("torch")
    pytest.importorskip("torch_geometric")
    from app.detectors import NODE_FEATURES, NUMERIC_EDGE_FEATURES, _hgt_class

    # a tiny untrained HGT with the shapes the detector expects; reuse a fitted preprocessing bundle
    joblib = pytest.importorskip("joblib")
    import numpy as np
    from sklearn.preprocessing import LabelEncoder, OneHotEncoder, StandardScaler

    settings = make_settings()
    import pandas as pd
    edges = pd.read_parquet(settings.replay_file)
    cats = ["most_common_service", "most_common_connection_state"]
    encoder = OneHotEncoder(handle_unknown="ignore", sparse_output=False).fit(edges[cats].fillna("unknown"))
    edge_dim = len(NUMERIC_EDGE_FEATURES) + len(encoder.get_feature_names_out())
    bundle = {"edge_scaler": StandardScaler().fit(np.zeros((2, len(NUMERIC_EDGE_FEATURES)))),
              "node_scaler": StandardScaler().fit(np.zeros((2, len(NODE_FEATURES)))),
              "edge_category_encoder": encoder,
              "tactic_encoder": LabelEncoder().fit(["Reconnaissance", "Initial Access"]),
              "mitre_encoder": LabelEncoder().fit(["T1190", "T1595", "T1110"])}
    joblib.dump(bundle, tmp_path / "pre.joblib")
    config = dict(node_input_dim=len(NODE_FEATURES), edge_input_dim=edge_dim, hidden_dim=8, tactic_dim=2, mitre_dim=3, heads=2)
    torch.save({"model_config": config, "model_state_dict": _hgt_class()(**config).state_dict(), "threshold": 0.5},
               tmp_path / "hgt.pt")

    app = create_app(make_settings(hgt_checkpoint=tmp_path / "hgt.pt", preprocessing_file=tmp_path / "pre.joblib",
                                   gnn_explainer=False))
    with TestClient(app, headers={"X-API-Key": API_KEY}) as c:
        c.post("/detect", json={})
        assert c.get("/incidents").json()["replay"]["window_index"] == 1
        body = c.post("/models/active", json={"model": "hgt"}).json()
        assert body["active"] == "hgt"
        replay = c.get("/incidents").json()
        assert replay["primary_model"] == "HGT"
        assert replay["replay"]["window_index"] == 0 and replay["incidents"] == []   # restarted
        assert c.post("/detect", json={}).status_code == 200


def test_knowledge_catalog_counts_chunks_per_technique(client):
    body = client.get("/knowledge-base").json()
    assert body["retrieval"] == "token overlap"
    by_id = {t["technique_id"]: t for t in body["techniques"]}
    assert by_id["T1190"]["procedure"] == 1 and by_id["T1190"]["mitigations"] == 2
    assert by_id["T1190"]["detector_class"] is True     # the test detector predicts T1190
    assert by_id["T1564"]["detector_class"] is False
    assert {s["source"] for s in body["sources"]} >= {"mitre", "procedure"}


def test_knowledge_technique_page(client):
    page = client.get("/knowledge-base/t1190").json()
    assert page["name"] == "Exploit Public-Facing Application"
    assert "(Citation" not in page["description"]
    assert "through Valid Accounts." in page["description"] and "](" not in page["description"]
    assert page["items"]["procedure"][0]["title"] == "Operation Web"
    assert [m["mitigation_id"] for m in page["mitigations"]] == ["M1050", "M1030"]
    assert client.get("/knowledge-base/T9999").status_code == 404


def test_knowledge_items_from_the_vector_store():
    chromadb = pytest.importorskip("chromadb")
    from app.vector_store import VectorStore
    chunks = [{"id": "c1", "text": "APT1 brute forced SSH.", "metadata": {"technique_ids": ["T1110"], "apt_group": "APT1", "report": "r1"}},
              {"id": "c2", "text": "Scanning.", "metadata": {"technique_ids": ["T1595"]}}]
    store = VectorStore.from_sources(chromadb.EphemeralClient(), lambda texts: [[1.0, 0.0, 0.0] for _ in texts],
                                     "dummy", {"cti": chunks})
    items = store.items("cti", "T1110")
    assert [i["id"] for i in items] == ["c1"]
    assert store.items("cti", "T1046") == []
