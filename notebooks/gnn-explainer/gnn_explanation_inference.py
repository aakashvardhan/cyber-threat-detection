import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.data import Data
from torch_geometric.nn import SAGEConv
from torch_geometric.explain import Explainer, GNNExplainer


NODE_FEATURE_NAMES = [
    "outgoing_edge_count",
    "outgoing_connection_count",
    "unique_destinations",
    "outgoing_duration",
    "outgoing_orig_bytes",
    "outgoing_orig_packets",
    "outgoing_orig_ip_bytes",
    "outgoing_missed_bytes",
    "outgoing_tcp_count",
    "outgoing_udp_count",
    "outgoing_icmp_count",
    "incoming_edge_count",
    "incoming_connection_count",
    "unique_sources",
    "incoming_duration",
    "incoming_resp_bytes",
    "incoming_resp_packets",
    "incoming_resp_ip_bytes",
    "incoming_missed_bytes",
    "incoming_tcp_count",
    "incoming_udp_count",
    "incoming_icmp_count"
]

NUMERIC_EDGE_FEATURE_NAMES = [
    "connection_count",
    "total_duration",
    "average_duration",
    "maximum_duration",
    "total_orig_bytes",
    "total_resp_bytes",
    "total_orig_packets",
    "total_resp_packets",
    "total_orig_ip_bytes",
    "total_resp_ip_bytes",
    "total_missed_bytes",
    "unique_destination_ports",
    "most_common_destination_port",
    "tcp_count",
    "udp_count",
    "icmp_count"
]


class GraphSAGEEdgeClassifier(nn.Module):
    def __init__(
        self,
        node_input_dim,
        edge_input_dim,
        hidden_dim,
        tactic_dim,
        mitre_dim,
        dropout=0.3
    ):
        super().__init__()

        self.conv1 = SAGEConv(node_input_dim, hidden_dim)
        self.conv2 = SAGEConv(hidden_dim, hidden_dim)
        self.dropout = dropout

        edge_input_size = hidden_dim * 2 + edge_input_dim

        self.binary_head = nn.Sequential(
            nn.Linear(edge_input_size, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, 1)
        )

        self.tactic_head = nn.Sequential(
            nn.Linear(edge_input_size, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, tactic_dim)
        )

        self.mitre_head = nn.Sequential(
            nn.Linear(edge_input_size, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, mitre_dim)
        )

    def forward(self, data):
        x = self.conv1(data.x, data.edge_index)
        x = F.relu(x)
        x = F.dropout(
            x,
            p=self.dropout,
            training=self.training
        )

        x = self.conv2(x, data.edge_index)
        x = F.relu(x)

        source_nodes = data.edge_index[0]
        destination_nodes = data.edge_index[1]

        edge_representation = torch.cat(
            [
                x[source_nodes],
                x[destination_nodes],
                data.edge_attr
            ],
            dim=1
        )

        binary_logits = self.binary_head(
            edge_representation
        ).squeeze(1)

        tactic_logits = self.tactic_head(edge_representation)
        mitre_logits = self.mitre_head(edge_representation)

        return binary_logits, tactic_logits, mitre_logits


class HeadWrapper(nn.Module):
    def __init__(self, model, task_name):
        super().__init__()
        self.model = model
        self.task_name = task_name

    def forward(self, x, edge_index, edge_attr):
        graph = Data(
            x=x,
            edge_index=edge_index,
            edge_attr=edge_attr
        )

        binary_logits, tactic_logits, mitre_logits = self.model(
            graph
        )

        if self.task_name == "binary":
            return binary_logits.unsqueeze(1)
        if self.task_name == "tactic":
            return tactic_logits
        return mitre_logits


def load_torch_file(path, device="cpu"):
    try:
        return torch.load(
            path,
            map_location=device,
            weights_only=False
        )
    except TypeError:
        return torch.load(path, map_location=device)


def json_safe(value):
    if isinstance(value, dict):
        return {
            str(key): json_safe(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    if isinstance(value, np.generic):
        return value.item()
    if pd.isna(value):
        return None
    return value


def safe_label_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, np.ndarray)):
        return [str(item) for item in value]
    if pd.isna(value):
        return []
    return [str(value)]


def get_ground_truth(row):
    if "binary_target" in row.index:
        binary_value = int(row["binary_target"])
    elif "label_binary" in row.index:
        binary_value = {
            "True": 1,
            "False": 0,
            "1": 1,
            "0": 0
        }.get(str(row["label_binary"]))
    else:
        binary_value = None

    tactic_column = (
        "tactic_targets"
        if "tactic_targets" in row.index
        else "label_tactic"
    )
    mitre_column = (
        "mitre_targets"
        if "mitre_targets" in row.index
        else "label_technique"
    )

    if binary_value is None and (
        tactic_column not in row.index
        and mitre_column not in row.index
    ):
        return None

    return {
        "label_binary": binary_value,
        "label_tactic": safe_label_list(
            row.get(tactic_column)
        ),
        "label_technique": safe_label_list(
            row.get(mitre_column)
        )
    }


def create_explainer(model, task_name, epochs):
    mode = (
        "binary_classification"
        if task_name == "binary"
        else "multiclass_classification"
    )

    return Explainer(
        model=HeadWrapper(model, task_name),
        algorithm=GNNExplainer(epochs=epochs),
        explanation_type="model",
        node_mask_type="attributes",
        edge_mask_type="object",
        model_config={
            "mode": mode,
            "task_level": "edge",
            "return_type": "raw"
        }
    )


def top_features(mask, feature_names, top_k):
    if mask is None:
        return []

    mask = mask.detach().cpu()
    importance = mask.abs()

    if importance.ndim == 2:
        importance = importance.mean(dim=0)

    importance = importance.numpy()
    order = np.argsort(importance)[::-1][:top_k]

    return [
        {
            "feature": str(feature_names[index]),
            "importance": float(importance[index])
        }
        for index in order
    ]


def top_neighbors(
    edge_mask,
    metadata,
    top_k,
    minimum_importance=1e-8
):
    if edge_mask is None:
        return []

    importance = edge_mask.detach().cpu().numpy()
    order = np.argsort(importance)[::-1]
    results = []

    for edge_index in order:
        if len(results) >= top_k:
            break
        if importance[edge_index] <= minimum_importance:
            continue

        row = metadata.iloc[edge_index]
        results.append({
            "source_ip": str(row["src_ip_zeek"]),
            "destination_ip": str(row["dest_ip_zeek"]),
            "importance": float(importance[edge_index])
        })

    return results


def target_logit(task_name, outputs, edge_index, target_index):
    binary_logits, tactic_logits, mitre_logits = outputs

    if task_name == "binary":
        return binary_logits[edge_index]
    if task_name == "tactic":
        return tactic_logits[edge_index, target_index]
    return mitre_logits[edge_index, target_index]


def edge_feature_faithfulness(
    model,
    graph,
    task_name,
    edge_index,
    target_index,
    important_features,
    edge_feature_names,
    device
):
    indices = [
        edge_feature_names.index(item["feature"])
        for item in important_features
        if item["feature"] in edge_feature_names
    ]

    if not indices:
        return None

    graph = graph.to(device)

    with torch.no_grad():
        original_outputs = model(graph)
        original_score = target_logit(
            task_name,
            original_outputs,
            edge_index,
            target_index
        )

        masked_edge_attr = graph.edge_attr.clone()
        masked_edge_attr[edge_index, indices] = 0.0

        masked_graph = Data(
            x=graph.x,
            edge_index=graph.edge_index,
            edge_attr=masked_edge_attr
        )

        masked_outputs = model(masked_graph)
        masked_score = target_logit(
            task_name,
            masked_outputs,
            edge_index,
            target_index
        )

    original_value = float(original_score.item())
    masked_value = float(masked_score.item())

    return {
        "original_logit": original_value,
        "masked_logit": masked_value,
        "logit_drop": original_value - masked_value
    }


def explain_task(
    model,
    graph,
    metadata,
    task_name,
    edge_index,
    target_index,
    node_feature_names,
    edge_feature_names,
    epochs,
    top_k_features,
    top_k_neighbors,
    device
):
    explainer = create_explainer(
        model,
        task_name,
        epochs
    )

    graph_device = graph.to(device)
    target = torch.tensor(
        [target_index],
        dtype=torch.long,
        device=device
    )

    explanation = explainer(
        x=graph_device.x,
        edge_index=graph_device.edge_index,
        edge_attr=graph_device.edge_attr,
        index=edge_index,
        target=target
    )

    important_node_features = top_features(
        explanation.node_mask,
        node_feature_names,
        top_k_features
    )

    important_edge_features = []

    edge_attributes = graph_device.edge_attr.detach().clone()
    edge_attributes.requires_grad_(True)

    gradient_outputs = HeadWrapper(
        model,
        task_name
    )(
        graph_device.x,
        graph_device.edge_index,
        edge_attributes
    )

    selected_score = target_logit(
        task_name,
        gradient_outputs,
        edge_index,
        target_index
    )

    model.zero_grad(set_to_none=True)
    selected_score.backward()

    gradient_importance = edge_attributes.grad[
        edge_index
    ].abs().detach().cpu().numpy()

    feature_order = np.argsort(
        gradient_importance
    )[::-1][:top_k_features]

    important_edge_features = [
        {
            "feature": str(edge_feature_names[index]),
            "importance": float(gradient_importance[index])
        }
        for index in feature_order
    ]

    return {
        "task": task_name,
        "target_index": int(target_index),
        "important_node_features": important_node_features,
        "important_edge_features": important_edge_features,
        "important_neighbor_edges": top_neighbors(
            explanation.edge_mask,
            metadata,
            top_k_neighbors
        )
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--checkpoint",
        default="graphsage_exp1_best_model.pt"
    )
    parser.add_argument(
        "--test-graphs",
        default="test_graphs.pt"
    )
    parser.add_argument(
        "--metadata",
        default="test_edges.parquet"
    )
    parser.add_argument(
        "--preprocessing",
        default="preprocessing_objects.joblib"
    )
    parser.add_argument(
        "--predictions-output",
        default="graphsage_test_predictions.jsonl"
    )
    parser.add_argument(
        "--explanations-output",
        default="gnn_explanations_ui.json"
    )
    parser.add_argument(
        "--num-explanations",
        type=int,
        default=20
    )
    parser.add_argument(
        "--explainer-epochs",
        type=int,
        default=100
    )
    parser.add_argument(
        "--top-k-features",
        type=int,
        default=5
    )
    parser.add_argument(
        "--top-k-neighbors",
        type=int,
        default=5
    )
    parser.add_argument(
        "--binary-threshold",
        type=float,
        default=0.5
    )
    args = parser.parse_args()

    device = torch.device(
        "cuda" if torch.cuda.is_available() else "cpu"
    )

    test_graphs = load_torch_file(args.test_graphs)
    checkpoint = load_torch_file(
        args.checkpoint,
        device=device
    )
    preprocessing = joblib.load(args.preprocessing)
    metadata = pd.read_parquet(args.metadata).reset_index(
        drop=True
    )

    tactic_encoder = preprocessing["tactic_encoder"]
    mitre_encoder = preprocessing["mitre_encoder"]
    edge_encoder = preprocessing["edge_category_encoder"]

    edge_feature_names = (
        NUMERIC_EDGE_FEATURE_NAMES
        + edge_encoder.get_feature_names_out([
            "most_common_service",
            "most_common_connection_state"
        ]).tolist()
    )

    model = GraphSAGEEdgeClassifier(
        **checkpoint["model_config"]
    ).to(device)
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()

    total_edges = sum(
        graph.num_edges for graph in test_graphs
    )

    if total_edges != len(metadata):
        raise ValueError(
            "The test metadata and graph edge counts do not match."
        )

    predictions = []
    graph_start = 0

    with torch.no_grad():
        for graph_index, graph in enumerate(test_graphs):
            graph_device = graph.to(device)
            outputs = model(graph_device)
            binary_logits, tactic_logits, mitre_logits = outputs

            binary_probabilities = torch.sigmoid(
                binary_logits
            ).cpu().numpy()
            tactic_probabilities = torch.sigmoid(
                tactic_logits
            ).cpu().numpy()
            mitre_probabilities = torch.sigmoid(
                mitre_logits
            ).cpu().numpy()

            graph_metadata = metadata.iloc[
                graph_start:graph_start + graph.num_edges
            ].reset_index(drop=True)

            for local_edge_index, row in graph_metadata.iterrows():
                global_index = graph_start + local_edge_index
                attack_probability = float(
                    binary_probabilities[local_edge_index]
                )
                tactic_index = int(
                    np.argmax(
                        tactic_probabilities[local_edge_index]
                    )
                )
                mitre_index = int(
                    np.argmax(
                        mitre_probabilities[local_edge_index]
                    )
                )

                predictions.append({
                    "row_id": global_index,
                    "graph_index": graph_index,
                    "local_edge_index": local_edge_index,
                    "window_start": row["window_start"],
                    "source_ip": str(row["src_ip_zeek"]),
                    "destination_ip": str(row["dest_ip_zeek"]),
                    "label": (
                        "attack"
                        if attack_probability >= args.binary_threshold
                        else "benign"
                    ),
                    "attack_probability": attack_probability,
                    "tactic_index": tactic_index,
                    "tactic_label": str(
                        tactic_encoder.classes_[tactic_index]
                    ),
                    "tactic_confidence": float(
                        tactic_probabilities[
                            local_edge_index,
                            tactic_index
                        ]
                    ),
                    "mitre_index": mitre_index,
                    "mitre_label": str(
                        mitre_encoder.classes_[mitre_index]
                    ),
                    "mitre_confidence": float(
                        mitre_probabilities[
                            local_edge_index,
                            mitre_index
                        ]
                    )
                })

            graph_start += graph.num_edges

    with open(
        args.predictions_output,
        "w",
        encoding="utf-8"
    ) as output_file:
        for prediction in predictions:
            output_file.write(
                json.dumps(json_safe(prediction))
                + "\n"
            )

    attack_predictions = [
        prediction
        for prediction in predictions
        if prediction["label"] == "attack"
    ]
    attack_predictions.sort(
        key=lambda item: item["attack_probability"],
        reverse=True
    )

    selected = attack_predictions[:args.num_explanations]

    if len(selected) < args.num_explanations:
        benign_predictions = [
            prediction
            for prediction in predictions
            if prediction["label"] == "benign"
        ]
        benign_predictions.sort(
            key=lambda item: item["attack_probability"]
        )
        selected.extend(
            benign_predictions[
                :args.num_explanations - len(selected)
            ]
        )

    ui_records = []

    for prediction in selected:
        graph = test_graphs[prediction["graph_index"]]
        graph_start = sum(
            item.num_edges
            for item in test_graphs[
                :prediction["graph_index"]
            ]
        )
        graph_metadata = metadata.iloc[
            graph_start:graph_start + graph.num_edges
        ].reset_index(drop=True)

        explanations = {}
        for task_name, target_index in [
            (
                "binary",
                int(prediction["label"] == "attack")
            ),
            ("tactic", prediction["tactic_index"]),
            ("mitre", prediction["mitre_index"])
        ]:
            explanations[task_name] = explain_task(
                model,
                graph,
                graph_metadata,
                task_name,
                prediction["local_edge_index"],
                target_index,
                NODE_FEATURE_NAMES,
                edge_feature_names,
                args.explainer_epochs,
                args.top_k_features,
                args.top_k_neighbors,
                device
            )

            explanations[task_name][
                "faithfulness"
            ] = edge_feature_faithfulness(
                model,
                graph,
                task_name,
                prediction["local_edge_index"],
                target_index,
                explanations[task_name][
                    "important_edge_features"
                ],
                edge_feature_names,
                device
            )

        window_start = prediction["window_start"]
        if hasattr(window_start, "isoformat"):
            window_start = window_start.isoformat()

        ui_records.append({
            "event_id": f"uwf-test-{prediction['row_id']}",
            "row_id": prediction["row_id"],
            "event": {
                "window_start": window_start,
                "source_ip": prediction["source_ip"],
                "destination_ip": prediction[
                    "destination_ip"
                ],
                "ground_truth": get_ground_truth(
                    metadata.iloc[prediction["row_id"]]
                )
            },
            "gnn_detection": {
                "binary_prediction": {
                    "label": prediction["label"],
                    "attack_probability": prediction[
                        "attack_probability"
                    ],
                    "confidence_type": "sigmoid"
                },
                "tactic_prediction": {
                    "label": prediction["tactic_label"],
                    "confidence": prediction[
                        "tactic_confidence"
                    ],
                    "confidence_type": "independent_sigmoid"
                },
                "mitre_prediction": {
                    "technique_id": prediction["mitre_label"],
                    "confidence": prediction[
                        "mitre_confidence"
                    ],
                    "confidence_type": "independent_sigmoid"
                }
            },
            "explanations": explanations
        })

    with open(
        args.explanations_output,
        "w",
        encoding="utf-8"
    ) as output_file:
        json.dump(
            json_safe(ui_records),
            output_file,
            indent=2
        )

    print("Device:", device)
    print("Test predictions:", len(predictions))
    print("Detailed explanations:", len(ui_records))
    print("Predictions saved to:", args.predictions_output)
    print("Explanations saved to:", args.explanations_output)


if __name__ == "__main__":
    main()
