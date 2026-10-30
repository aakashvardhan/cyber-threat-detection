"""Knowledge base and retrieval for incident evidence.

Reads the processed ATT&CK files used by the Oct 6 demo (mitre_lookup.csv,
mitre_mitigations.csv, procedure_chunks.jsonl) plus optional cti_chunks.jsonl and
cve_chunks.jsonl. When the vector store is available (app/vector_store.py) evidence comes
from the RAG notebook's vector retrieval; otherwise from the demo's token-overlap score.
"""
from __future__ import annotations

import json
import math
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

# tactics renamed in newer ATT&CK releases; UWF labels still use the old names
TACTIC_ALIASES = {"Defense Evasion": ["Defense Evasion", "Stealth", "Defense Impairment"]}
CVE_TECHNIQUES = {"T1190", "T1210", "T1203", "T1211", "T1212", "T1068"}


def _tokens(text: str) -> set[str]:
    return {t for t in re.findall(r"[a-z0-9]+", (text or "").lower()) if len(t) > 2}


def _score(query: set[str], text: str) -> float:
    doc = _tokens(text)
    if not query or not doc:
        return 0.0
    return len(query & doc) / math.sqrt(len(query) * len(doc))


def _first_sentences(text: str, limit: int = 400) -> str:
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= limit else text[: limit - 1].rsplit(" ", 1)[0] + "…"


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open("rb") as handle:
        if handle.read(40).startswith(b"version https://git-lfs"):   # Git LFS pointer, file not pulled
            return []
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


@dataclass
class Retrieval:
    evidence: list[dict]
    trace: dict
    cve_status: str
    fallback_to_tactic: bool = False


@dataclass
class KnowledgeBase:
    techniques: dict[str, dict] = field(default_factory=dict)
    mitigations: dict[str, list[dict]] = field(default_factory=dict)
    chunks: dict[str, list[dict]] = field(default_factory=dict)   # source -> chunks
    by_technique: dict[str, dict[str, list[dict]]] = field(default_factory=dict)
    directory: str | None = None
    vector: object | None = None      # VectorStore, set by build_state when vector retrieval is on

    @classmethod
    def load(cls, directory: Path | None) -> "KnowledgeBase":
        kb = cls(directory=str(directory) if directory else None)
        if directory is None or not Path(directory).exists():
            return kb
        directory = Path(directory)
        lookup = directory / "mitre_lookup.csv"
        if lookup.exists():
            for row in pd.read_csv(lookup, dtype=str, keep_default_na=False).to_dict("records"):
                kb.techniques[str(row["technique_id"])] = row
        mitigations = directory / "mitre_mitigations.csv"
        if mitigations.exists():
            frame = pd.read_csv(mitigations, dtype=str, keep_default_na=False)
            for tid, group in frame.groupby("technique_id"):
                kb.mitigations[str(tid)] = (group.drop_duplicates("mitigation_id")
                                            [["mitigation_id", "mitigation_name"]]
                                            .rename(columns={"mitigation_name": "name"}).to_dict("records"))
        for source, filename in [("procedure", "procedure_chunks.jsonl"), ("cti", "cti_chunks.jsonl"),
                                 ("cve", "cve_chunks.jsonl")]:
            kb.add_chunks(source, _read_jsonl(directory / filename))
        return kb

    def add_chunks(self, source: str, chunks: list[dict]) -> None:
        self.chunks[source] = chunks
        index: dict[str, list[dict]] = {}
        for chunk in chunks:
            meta = chunk.get("metadata", {})
            ids = meta.get("technique_ids") or []
            ids = [ids] if isinstance(ids, str) else list(ids)
            if meta.get("technique_id"):
                ids.append(meta["technique_id"])
            for tid in {str(t).split(".")[0] for t in ids}:
                index.setdefault(tid, []).append(chunk)
        self.by_technique[source] = index

    # ----- lookups -----
    def technique(self, technique_id: str | None) -> dict | None:
        if not technique_id:
            return None
        return self.techniques.get(technique_id) or self.techniques.get(technique_id.split(".")[0])

    def technique_name(self, technique_id: str | None) -> str:
        info = self.technique(technique_id)
        return str(info["name"]) if info else (technique_id or "Unknown technique")

    def tactics_of(self, technique_id: str | None) -> list[str]:
        info = self.technique(technique_id)
        return [t for t in str(info.get("tactics", "")).split(", ") if t] if info else []

    def mitigations_for(self, technique_id: str | None) -> list[dict]:
        if not technique_id:
            return []
        return self.mitigations.get(technique_id) or self.mitigations.get(technique_id.split(".")[0], [])

    def techniques_in_tactic(self, tactic: str) -> list[str]:
        names = set(TACTIC_ALIASES.get(tactic, [tactic]))
        return sorted({str(row["parent_id"] or tid).split(".")[0] for tid, row in self.techniques.items()
                       if names & set(str(row.get("tactics", "")).split(", "))})

    # ----- retrieval -----
    def retrieve(self, technique_id: str | None, tactic: str | None, query: str,
                 top_k: int = 5, min_score: float = 0.05, event: dict | None = None) -> Retrieval:
        if self.vector is not None and event is not None:
            return self._retrieve_vector(technique_id, tactic, event, top_k, min_score)
        started = time.perf_counter()
        q = _tokens(query)
        evidence: list[dict] = []
        sources: list[dict] = []
        parent = technique_id.split(".")[0] if technique_id else None

        info = self.technique(technique_id)
        if info:
            evidence.append({"source": "mitre", "level": "technique", "ref": str(info["technique_id"]),
                             "title": str(info["name"]), "text": _first_sentences(str(info.get("description", ""))),
                             "score": 1.0, "url": str(info.get("url")) or None})
        sources.append({"source": "mitre", "returned": 1 if info else 0})

        def ranked(source: str, technique_ids: list[str], level: str) -> tuple[int, list[dict]]:
            index = self.by_technique.get(source, {})
            candidates, seen = [], set()
            for tid in technique_ids:
                for chunk in index.get(tid, []):
                    if chunk.get("id") not in seen:
                        seen.add(chunk.get("id"))
                        candidates.append(chunk)
            scored = sorted(((_score(q, c.get("text", "")), c) for c in candidates), key=lambda x: -x[0])
            hits = []
            for score, chunk in scored:
                if score < min_score or len(hits) >= top_k:
                    break
                meta = chunk.get("metadata", {})
                hits.append({"source": source, "level": level,
                             "ref": meta.get("source_attack_id") or meta.get("cve_id") or meta.get("technique_id") or chunk.get("id"),
                             "title": meta.get("source_name") or meta.get("product") or meta.get("cve_id") or source.upper(),
                             "text": _first_sentences(chunk.get("text", "")), "score": round(score, 3),
                             "url": meta.get("url")})
            return len(candidates), hits

        fallback = False
        technique_hits: list[dict] = []
        for source in ("procedure", "cti"):
            if not self.chunks.get(source):
                sources.append({"source": source, "returned": 0, "skipped": True})
                continue
            searched, hits = ranked(source, [parent] if parent else [], "technique")
            if not hits and tactic:
                siblings = [t for t in self.techniques_in_tactic(tactic) if t != parent]
                searched_tactic, hits = ranked(source, siblings, "tactic")
                searched += searched_tactic
                fallback = fallback or bool(hits)
            technique_hits.extend(hits)
            sources.append({"source": source, "searched": searched, "returned": len(hits)})
        technique_hits.sort(key=lambda e: -e["score"])
        evidence.extend(technique_hits[:top_k])
        returned = {s: sum(e["source"] == s for e in evidence) for s in ("procedure", "cti")}
        for s in sources:
            if s["source"] in returned and not s.get("skipped"):
                s["returned"] = returned[s["source"]]

        cve_applicable = parent in CVE_TECHNIQUES and bool(self.chunks.get("cve"))
        if cve_applicable:
            searched, hits = ranked("cve", [parent], "cve")
            evidence.extend(hits[:2])
            sources.append({"source": "cve", "searched": searched, "returned": len(hits[:2])})
        else:
            sources.append({"source": "cve", "returned": 0, "skipped": True})

        for i, item in enumerate(evidence, start=1):
            item["evidence_id"] = f"E{i}"
        trace = {"query": query, "sources": sources, "top_k": top_k, "min_score": min_score,
                 "fallback_to_tactic": fallback, "latency_ms": int((time.perf_counter() - started) * 1000)}
        return Retrieval(evidence, trace, "applicable" if cve_applicable else "not_applicable", fallback)

    def _mitre_evidence(self, technique_id: str | None) -> list[dict]:
        info = self.technique(technique_id)
        if not info:
            return []
        return [{"source": "mitre", "level": "technique", "ref": str(info["technique_id"]), "title": str(info["name"]),
                 "text": _first_sentences(str(info.get("description", ""))), "score": 1.0, "url": str(info.get("url")) or None}]

    def _retrieve_vector(self, technique_id: str | None, tactic: str | None, event: dict, top_k: int,
                         min_score: float = 0.05) -> Retrieval:
        """RAG notebook flow (vector search with technique filter and fallbacks)."""
        started = time.perf_counter()
        parent = technique_id.split(".")[0] if technique_id else None
        siblings = [t for t in self.techniques_in_tactic(tactic) if t != parent] if tactic else []
        result = self.vector.retrieve({**event, "technique_id": technique_id,
                                       "technique_name": self.technique_name(technique_id)}, siblings, k_cti=top_k,
                                      min_score=min_score)
        evidence = self._mitre_evidence(technique_id) + result["evidence"]
        for i, item in enumerate(evidence, start=1):
            item["evidence_id"] = f"E{i}"
        sources = [{"source": "mitre", "returned": 1 if self.technique(technique_id) else 0}] + result["sources"]
        cve_applicable = any(s["source"] == "cve" and not s.get("skipped") for s in sources)
        trace = {"query": result["query"], "sources": sources, "top_k": top_k, "min_score": min_score,
                 "fallback_to_tactic": result["fallback_to_tactic"],
                 "latency_ms": int((time.perf_counter() - started) * 1000)}
        return Retrieval(evidence, trace, "applicable" if cve_applicable else "not_applicable", result["fallback_to_tactic"])

    # ----- /metrics knowledge_base block -----
    def stats(self, techniques_of_interest: list[str]) -> dict:
        if self.vector is not None:
            counts = self.vector.counts
            sources = [{"source": "mitre", "items": len(self.techniques), "chunks": len(self.techniques),
                        "techniques_linked": len(self.techniques)}]
            for source, col in (("procedure", "procedures"), ("cti", "cti"), ("cve", "cve")):
                n = self.vector.cols[col].count() if col in self.vector.cols else 0
                sources.append({"source": source, "items": n, "chunks": n, "techniques_linked": len(counts.get(col, {}))})
            coverage = []
            for tid in techniques_of_interest:
                n = sum(counts.get(c, {}).get(tid.split(".")[0], 0) for c in ("procedures", "cti"))
                coverage.append({"technique_id": tid, "technique_level_chunks": n, "tactic_only": n == 0})
            return {"embedding_model": self.vector.model_name, "sources": sources, "coverage": coverage}
        sources = [{"source": "mitre", "items": len(self.techniques), "chunks": len(self.techniques),
                    "techniques_linked": len(self.techniques)}]
        for source in ("procedure", "cti", "cve"):
            chunks = self.chunks.get(source, [])
            sources.append({"source": source, "items": len(chunks), "chunks": len(chunks),
                            "techniques_linked": len(self.by_technique.get(source, {}))})
        coverage = []
        for tid in techniques_of_interest:
            count = sum(len(self.by_technique.get(s, {}).get(tid.split(".")[0], [])) for s in ("procedure", "cti"))
            coverage.append({"technique_id": tid, "technique_level_chunks": count, "tactic_only": count == 0})
        return {"embedding_model": "token-overlap (no embeddings)", "sources": sources, "coverage": coverage}
