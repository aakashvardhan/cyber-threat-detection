"""Cross-encoder reranking of GraphRAG's text evidence (a fake cross-encoder; the real model is not needed)."""
from types import SimpleNamespace

from app.attack_graph import NetworkXStore
from app.graph_rag import GraphRetriever
from app.knowledge import KnowledgeBase
from app.rerank import Reranker, load_reranker
from test_graph_rag import graph  # noqa: F401 - fixture


class KeywordEncoder:
    """Scores a (query, text) pair by whether the text mentions 'RDP'."""

    def __init__(self):
        self.pairs = []

    def predict(self, pairs, **_):
        self.pairs += pairs
        return [4.0 if "RDP" in text else -4.0 for _, text in pairs]


def test_reranker_reorders_and_keeps_the_tail():
    r = Reranker(KeywordEncoder(), "fake", candidates=3)
    items = [(0.9, {"text": "a"}, []), (0.8, {"text": "b RDP"}, []), (0.7, {"text": "c"}, []), (0.1, {"text": "d RDP"}, [])]
    out, trace = r.rerank("q", items, lambda x: x[1]["text"])
    assert [x[1]["text"] for x in out] == ["b RDP", "a", "c", "d RDP"]       # d is beyond the candidates: not rescored
    assert out[0][0] > 0.9 and out[1][0] < 0.1
    assert trace == {"model": "fake", "candidates": 3, "order_changed": True, "latency_ms": trace["latency_ms"]}


def test_graph_retrieval_uses_the_reranker(graph):  # noqa: F811
    query = "T1110 Brute Force Credential Access rdp 3389"
    plain = GraphRetriever(graph, NetworkXStore(graph), KnowledgeBase()).retrieve("T1110", None, query, 1)
    encoder = KeywordEncoder()
    reranked = GraphRetriever(graph, NetworkXStore(graph), KnowledgeBase(), Reranker(encoder, "fake")).retrieve(
        "T1110", None, query, 1)
    text = lambda r: [e["text"] for e in r.evidence if e["source"] in ("procedure", "cti")]
    assert "RDP" in text(reranked)[0]
    assert text(plain) != text(reranked)
    assert all(q == query for q, _ in encoder.pairs)
    assert reranked.trace["rerank"]["model"] == "fake" and reranked.trace["rerank"]["candidates"] >= 2
    assert plain.trace["rerank"] is None


def test_reranker_off_or_missing_model():
    assert load_reranker(SimpleNamespace(rerank=False)) is None
    assert load_reranker(SimpleNamespace(rerank=True, rerank_model="/no/such/model", rerank_candidates=30)) is None
