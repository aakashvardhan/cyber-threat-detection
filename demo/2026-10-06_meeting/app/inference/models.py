"""GraphSAGE model definitions (Combined_Model_Inference_v2)."""
from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import SAGEConv


class BinaryGraphSAGE(nn.Module):
    def __init__(self, hidden_size: int = 64, dropout: float = 0.2):
        super().__init__()
        self.conv1 = SAGEConv(6, hidden_size)
        self.conv2 = SAGEConv(hidden_size, hidden_size)
        self.edge_classifier = nn.Sequential(
            nn.Linear(hidden_size * 2 + 10, hidden_size),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_size, 1),
        )
        self.dropout = dropout

    def forward(self, data):
        x = F.relu(self.conv1(data.x, data.edge_index))
        x = F.dropout(x, p=self.dropout, training=self.training)
        x = F.relu(self.conv2(x, data.edge_index))
        src, dst = data.target_edge_index
        return self.edge_classifier(
            torch.cat([x[src], x[dst], data.target_edge_attr], dim=1)
        ).squeeze(-1)


class EdgeLabelGraphSAGE(nn.Module):
    def __init__(self, num_classes: int, hidden_size: int = 64, dropout: float = 0.2):
        super().__init__()
        self.conv1 = SAGEConv(6, hidden_size)
        self.conv2 = SAGEConv(hidden_size, hidden_size)
        self.classifier = nn.Sequential(
            nn.Linear(hidden_size * 2 + 10, hidden_size),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_size, num_classes),
        )
        self.dropout = dropout

    def forward(self, data):
        x = F.relu(self.conv1(data.x, data.edge_index))
        x = F.dropout(x, p=self.dropout, training=self.training)
        x = F.relu(self.conv2(x, data.edge_index))
        src, dst = data.target_edge_index
        return self.classifier(
            torch.cat([x[src], x[dst], data.target_edge_attr], dim=1)
        )
