"""Cross-encoder reranking of the text evidence (procedure examples and CTI report spans).

GraphRAG first collects candidate texts from the knowledge graph and orders them by graph importance plus word
overlap with the incident. A cross-encoder then reads the incident query and each candidate together and scores how
well the text answers it; the evidence is taken in that order (with the same per-report and per-source limits).

    RERANK=true|false        on by default when the model can be loaded
    RERANK_MODEL             default cross-encoder/ms-marco-MiniLM-L-6-v2 (22M parameters, fast on CPU);
                             e.g. BAAI/bge-reranker-base is more accurate but about 10x slower on CPU
    RERANK_CANDIDATES        how many first-stage candidates are rescored (default 30)

If the model cannot be loaded the backend logs a warning and keeps the first-stage order.
"""
from __future__ import annotations

import logging
import math
import threading
import time

log = logging.getLogger(__name__)


class Reranker:
    def __init__(self, model, name: str, candidates: int = 30):
        self.model = model
        self.name = name
        self.candidates = candidates
        self.lock = threading.Lock()          # explanations run in worker threads; one forward pass at a time

    @classmethod
    def load(cls, name: str, candidates: int = 30) -> "Reranker":
        from sentence_transformers import CrossEncoder
        return cls(CrossEncoder(name, max_length=256, device="cpu"), name, candidates)

    def score(self, query: str, texts: list[str]) -> list[float]:
        """Relevance in [0, 1] for each text (sigmoid of the cross-encoder logit)."""
        if not texts:
            return []
        with self.lock:
            logits = self.model.predict([(query, t) for t in texts], batch_size=32, show_progress_bar=False)
        return [1 / (1 + math.exp(-float(x))) for x in logits]

    def rerank(self, query: str, items: list, text_of) -> tuple[list, dict]:
        """Reorder the first `candidates` items by cross-encoder score; the rest keep their order after them.

        Returns (items, trace) where each rescored item is a (score, item, ...) tuple with the new score first."""
        started = time.perf_counter()
        head, tail = items[:self.candidates], items[self.candidates:]
        scores = self.score(query, [text_of(x) for x in head])
        order = sorted(range(len(head)), key=lambda i: -scores[i])
        reranked = [(round(scores[i], 4), *head[i][1:]) for i in order]
        trace = {"model": self.name, "candidates": len(head), "order_changed": order != list(range(len(head))),
                 "latency_ms": int((time.perf_counter() - started) * 1000)}
        return reranked + tail, trace


def load_reranker(settings) -> Reranker | None:
    if not settings.rerank:
        return None
    try:
        reranker = Reranker.load(settings.rerank_model, settings.rerank_candidates)
        log.info("Reranker: %s (top %d candidates)", settings.rerank_model, settings.rerank_candidates)
        return reranker
    except Exception as exc:  # noqa: BLE001 - keep the first-stage order
        log.warning("Reranker off: cannot load %s (%s: %s)", settings.rerank_model, type(exc).__name__, exc)
        return None
