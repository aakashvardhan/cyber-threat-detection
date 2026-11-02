"""Why the GraphSAGE model flagged an edge (GNNExplainer), for the incident page.

Adapted from Sai's gnn_explanation_inference.py (explain_task + edge_feature_faithfulness):
- neighbour edges: GNNExplainer edge mask on the binary head (which links the 2-layer GraphSAGE relied on)
- node features: GNNExplainer node-feature mask, averaged over the window's nodes
- edge features: gradient saliency of the binary logit w.r.t. the explained edge's features
- faithfulness: the attack probability again with the top edge features set to 0 (the training mean,
  since the numeric features are standard-scaled; for a one-hot category, "not this category")

The graph is built from the window's rows by the detector itself, so edge i is row i of the window.
Explaining one edge takes a few seconds on CPU, so it runs in a background thread on first request
and the result is cached per incident.
"""
from __future__ import annotations

import copy
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import numpy as np

from app.incidents import Incident
from app.timeutil import iso, now_iso

log = logging.getLogger(__name__)

TOP_FEATURES = 5
TOP_NEIGHBOURS = 6

LABELS = {
    "connection_count": "Connections on this link",
    "total_duration": "Total connection time",
    "average_duration": "Average connection time",
    "maximum_duration": "Longest connection",
    "total_orig_bytes": "Bytes sent",
    "total_resp_bytes": "Bytes received",
    "total_orig_packets": "Packets sent",
    "total_resp_packets": "Packets received",
    "total_orig_ip_bytes": "IP bytes sent",
    "total_resp_ip_bytes": "IP bytes received",
    "total_missed_bytes": "Missed bytes",
    "unique_destination_ports": "Distinct destination ports",
    "most_common_destination_port": "Most common destination port",
    "tcp_count": "TCP connections",
    "udp_count": "UDP connections",
    "icmp_count": "ICMP connections",
    "outgoing_edge_count": "Hosts contacted",
    "outgoing_connection_count": "Outgoing connections",
    "unique_destinations": "Distinct destinations",
    "outgoing_duration": "Outgoing connection time",
    "outgoing_orig_bytes": "Bytes sent (host)",
    "outgoing_orig_packets": "Packets sent (host)",
    "outgoing_orig_ip_bytes": "IP bytes sent (host)",
    "outgoing_missed_bytes": "Missed bytes sent (host)",
    "outgoing_tcp_count": "Outgoing TCP connections",
    "outgoing_udp_count": "Outgoing UDP connections",
    "outgoing_icmp_count": "Outgoing ICMP connections",
    "incoming_edge_count": "Hosts connecting in",
    "incoming_connection_count": "Incoming connections",
    "unique_sources": "Distinct sources",
    "incoming_duration": "Incoming connection time",
    "incoming_resp_bytes": "Bytes answered (host)",
    "incoming_resp_packets": "Packets answered (host)",
    "incoming_resp_ip_bytes": "IP bytes answered (host)",
    "incoming_missed_bytes": "Missed bytes received (host)",
    "incoming_tcp_count": "Incoming TCP connections",
    "incoming_udp_count": "Incoming UDP connections",
    "incoming_icmp_count": "Incoming ICMP connections",
}
STATE_MEANING = {"S0": "no reply", "SF": "completed", "REJ": "rejected", "RSTO": "reset by source",
                 "RSTR": "reset by target", "SH": "half open", "SHR": "half open", "OTH": "no handshake",
                 "S1": "established", "RSTOS0": "reset, no reply", "RSTRH": "reset by target"}


def feature_label(name: str) -> str:
    if name in LABELS:
        return LABELS[name]
    for prefix, title in (("most_common_connection_state_", "Connection state"), ("most_common_service_", "Service")):
        if name.startswith(prefix):
            value = name[len(prefix):]
            meaning = STATE_MEANING.get(value)
            return f"{title} = {value}" + (f" ({meaning})" if meaning else "")
    return name.replace("_", " ")


def _raw_value(row, name: str):
    """The edge's own value of a feature, as recorded in the window (not scaled)."""
    for prefix, column in (("most_common_connection_state_", "most_common_connection_state"),
                           ("most_common_service_", "most_common_service")):
        if name.startswith(prefix):
            actual = row.get(column)
            return "unknown" if actual is None or actual != actual else str(actual)   # the detector fills NaN with "unknown"
    value = row.get(name)
    try:
        value = float(value)
    except (TypeError, ValueError):
        return None
    return None if np.isnan(value) else (int(value) if value.is_integer() else round(value, 3))


def _shares(values: np.ndarray) -> np.ndarray:
    top = float(values.max()) if len(values) else 0.0
    return values / top if top > 0 else values


def explain_edge(model, data, edge_idx: int, edge_names: list[str], node_names: list[str], epochs: int = 100, seed: int = 0) -> dict:
    """Raw explanation of one edge's binary (attack) prediction; arrays follow the graph's order."""
    import torch
    from torch_geometric.data import Data
    from torch_geometric.explain import Explainer, GNNExplainer

    class BinaryHead(torch.nn.Module):
        def __init__(self, inner):
            super().__init__()
            self.inner = inner

        def forward(self, x, edge_index, edge_attr):
            return self.inner(Data(x=x, edge_index=edge_index, edge_attr=edge_attr))[0].unsqueeze(1)

    head = BinaryHead(model).eval()   # eval on the wrapper too: Explainer restores the wrapper's mode afterwards
    torch.manual_seed(seed)
    explainer = Explainer(model=head, algorithm=GNNExplainer(epochs=epochs), explanation_type="model",
                          node_mask_type="attributes", edge_mask_type="object",
                          model_config={"mode": "binary_classification", "task_level": "edge", "return_type": "raw"})
    explanation = explainer(x=data.x, edge_index=data.edge_index, edge_attr=data.edge_attr, index=edge_idx)
    head.eval()                       # dropout off for the gradient and faithfulness passes
    edge_mask = explanation.edge_mask.detach().cpu().numpy()
    node_importance = explanation.node_mask.detach().abs().mean(dim=0).cpu().numpy()

    attr = data.edge_attr.detach().clone().requires_grad_(True)
    logit = head(data.x, data.edge_index, attr)[edge_idx, 0]
    model.zero_grad(set_to_none=True)
    logit.backward()
    edge_importance = attr.grad[edge_idx].abs().detach().cpu().numpy()

    top_edge = list(np.argsort(edge_importance)[::-1][:TOP_FEATURES])
    with torch.no_grad():
        masked = data.edge_attr.clone()
        masked[edge_idx, top_edge] = 0.0
        before = float(head(data.x, data.edge_index, data.edge_attr)[edge_idx, 0])
        after = float(head(data.x, data.edge_index, masked)[edge_idx, 0])
    return {"edge_mask": edge_mask, "edge_feature_importance": edge_importance, "node_feature_importance": node_importance,
            "faithfulness": {"features": [edge_names[i] for i in top_edge], "logit_before": before, "logit_after": after},
            "probability": float(1 / (1 + np.exp(-before)))}


def present(raw: dict, rows, edge_idx: int, edge_names: list[str], node_names: list[str]) -> dict:
    """Readable top features, neighbour links and faithfulness for the UI."""
    row = rows.iloc[edge_idx]
    ef, nf, em = raw["edge_feature_importance"], raw["node_feature_importance"], raw["edge_mask"]
    e_share, n_share, m_share = _shares(ef), _shares(nf), _shares(em)
    edge_features = [{"feature": edge_names[i], "label": feature_label(edge_names[i]), "importance": round(float(ef[i]), 6),
                      "share": round(float(e_share[i]), 4), "value": _raw_value(row, edge_names[i])}
                     for i in np.argsort(ef)[::-1][:TOP_FEATURES]]
    node_features = [{"feature": node_names[i], "label": feature_label(node_names[i]), "importance": round(float(nf[i]), 6),
                      "share": round(float(n_share[i]), 4)} for i in np.argsort(nf)[::-1][:TOP_FEATURES]]
    neighbours = []
    for i in np.argsort(em)[::-1]:
        if len(neighbours) >= TOP_NEIGHBOURS or em[i] <= 1e-6:
            break
        r = rows.iloc[int(i)]
        neighbours.append({"source_ip": str(r["src_ip_zeek"]), "destination_ip": str(r["dest_ip_zeek"]),
                           "importance": round(float(em[i]), 6), "share": round(float(m_share[i]), 4),
                           "is_explained_edge": int(i) == edge_idx})
    f = raw["faithfulness"]
    sigmoid = lambda z: 1 / (1 + np.exp(-z))
    return {"edge_features": edge_features, "node_features": node_features, "neighbor_edges": neighbours,
            "faithfulness": {"features_removed": [feature_label(n) for n in f["features"]],
                             "probability_before": round(float(sigmoid(f["logit_before"])), 4),
                             "probability_after": round(float(sigmoid(f["logit_after"])), 4),
                             "logit_drop": round(f["logit_before"] - f["logit_after"], 4)}}


class ModelExplainer:
    """Background GNNExplainer runs, one per incident, for the incident's highest-probability edge."""

    def __init__(self, detector, data, epochs: int = 100, enabled: bool = True):
        self.detector, self.data, self.epochs = detector, data, epochs
        self.enabled = enabled and hasattr(detector, "build_graph") and hasattr(detector, "model")
        # GNNExplainer puts masks on the conv layers while it runs, so it gets its own copy of the model
        self.model = copy.deepcopy(detector.model) if self.enabled else None
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="gnn-explain")
        self.lock = threading.Lock()
        self.results: dict[str, dict] = {}

    @property
    def method(self) -> str:
        return (f"GNNExplainer ({self.epochs} epochs) on the GraphSAGE attack head; "
                "edge features by gradient saliency")

    def view(self, incident: Incident) -> dict:
        if not self.enabled:
            return {"status": "unavailable", "message": "Only the GraphSAGE model can be explained this way."}
        edge = max(incident.edges, key=lambda e: (e.attack_probability, -e.row))
        key = f"{edge.row}"
        with self.lock:
            current = self.results.get(incident.incident_id)
            if current is None or current["_key"] != key:
                current = {"_key": key, "status": "computing", "started_at": now_iso(), "edge": self._edge(edge)}
                self.results[incident.incident_id] = current
                self.pool.submit(self._run, incident.incident_id, edge, key)
            return {k: v for k, v in current.items() if not k.startswith("_")}

    @staticmethod
    def _edge(edge) -> dict:
        return {"event_id": edge.event_id, "window_start": iso(edge.window_start), "source_ip": edge.source_ip,
                "destination_ip": edge.destination_ip, "attack_probability": round(edge.attack_probability, 4)}

    def _run(self, incident_id: str, edge, key: str) -> None:
        started = time.perf_counter()
        try:
            rows = self.data.rows(edge.window_start)
            edge_idx = int(rows.index.get_loc(edge.row))
            graph = self.detector.build_graph(rows)
            names_e, names_n = self.detector.edge_feature_names, self.detector.node_feature_names
            raw = explain_edge(self.model, graph, edge_idx, names_e, names_n, self.epochs)
            update = {"status": "ready", "method": self.method, **present(raw, rows, edge_idx, names_e, names_n),
                      "seconds": round(time.perf_counter() - started, 2), "computed_at": now_iso()}
        except Exception as exc:  # noqa: BLE001 - shown on the page instead of failing the request
            log.exception("GNN explanation failed for %s", incident_id)
            update = {"status": "error", "message": f"{type(exc).__name__}: {exc}"}
        with self.lock:
            current = self.results.get(incident_id)
            if current is not None and current["_key"] == key:
                current.update(update)
