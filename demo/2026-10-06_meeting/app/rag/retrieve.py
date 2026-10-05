"""RAG retrieval engine adapted from rag.ipynb for local app/data/rag artifacts."""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any

import pandas as pd

from app.rag.attack_parse import read_jsonl
from app.rag.paths import (
    CTI_CHUNKS_JSONL,
    CVE_CHUNKS_JSONL,
    CVE_MODE,
    CVE_TECHNIQUES,
    MITRE_LOOKUP_CSV,
    PROCEDURE_CHUNKS_JSONL,
    SERVICE_KEYWORDS,
)


def _first_sentence(text: str | None) -> str:
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    text = re.sub(r"\s+([.,;])", r"\1", text).strip()
    return re.split(r"(?<=\.)\s", text, maxsplit=1)[0]


def _resolve_ids(event: dict) -> tuple[str | None, str | None]:
    tid = str(event.get("technique_id") or "").strip()
    tactic = event.get("tactic") or None
    if tid.endswith("_unspecified"):
        tactic, tid = tactic or tid[: -len("_unspecified")], None
    elif not re.fullmatch(r"T\d{4}(\.\d{3})?", tid):
        tid = None
    return tid, tactic


def _token_score(query: str, text: str) -> float:
    q = {t for t in re.findall(r"[a-z0-9]+", query.lower()) if len(t) > 2}
    d = {t for t in re.findall(r"[a-z0-9]+", text.lower()) if len(t) > 2}
    if not q or not d:
        return 0.0
    return len(q & d) / math.sqrt(len(q) * len(d))


@dataclass
class RetrievalResult:
    event: dict[str, Any]
    mitre: dict[str, Any] | None
    tactics: list[str]
    cve_mode: str | None
    cve: list[dict[str, Any]]
    cti: list[dict[str, Any]]

    def sources_for_llm(self, max_each: int = 3) -> list[dict[str, Any]]:
        sources: list[dict[str, Any]] = []
        if self.mitre:
            sources.append(
                {
                    "type": "mitre",
                    "id": self.mitre.get("technique_id"),
                    "title": self.mitre.get("name"),
                    "text": _first_sentence(self.mitre.get("description")),
                    "mitigations": (self.mitre.get("mitigations") or "")[:400],
                }
            )
        for row in self.cti[:max_each]:
            sources.append(
                {
                    "type": row.get("evidence_level", "cti"),
                    "id": row.get("id") or row.get("technique_id") or "",
                    "title": row.get("source_name") or row.get("apt_group") or "CTI/procedure",
                    "text": row.get("text", "")[:500],
                    "score": row.get("score"),
                }
            )
        for row in self.cve[:max_each]:
            sources.append(
                {
                    "type": "cve",
                    "id": row.get("cve_id", ""),
                    "title": row.get("product") or row.get("cve_id") or "CVE",
                    "text": row.get("text", "")[:500],
                    "score": row.get("score"),
                }
            )
        return sources


class RAGEngine:
    """Technique-gated retrieval using MITRE lookup + procedure/CTI/CVE chunk files."""

    def __init__(self) -> None:
        if not MITRE_LOOKUP_CSV.exists():
            raise FileNotFoundError(
                f"Missing {MITRE_LOOKUP_CSV}. Run: python -m app.rag.bootstrap"
            )
        self.mitre_lookup = pd.read_csv(MITRE_LOOKUP_CSV).fillna("")
        self.mitre_index = self.mitre_lookup.set_index("technique_id", drop=False)
        self.procedure_chunks = read_jsonl(PROCEDURE_CHUNKS_JSONL)
        self.cti_chunks = read_jsonl(CTI_CHUNKS_JSONL)
        self.cve_chunks = read_jsonl(CVE_CHUNKS_JSONL)
        self._proc_by_tech = self._index_by_technique(self.procedure_chunks)
        self._cti_by_tech = self._index_by_technique(self.cti_chunks)

    @staticmethod
    def _index_by_technique(chunks: list[dict]) -> dict[str, list[dict]]:
        index: dict[str, list[dict]] = {}
        for chunk in chunks:
            ids = chunk.get("metadata", {}).get("technique_ids") or []
            if isinstance(ids, str):
                ids = [ids]
            for tid in ids:
                index.setdefault(str(tid), []).append(chunk)
            tid = chunk.get("metadata", {}).get("technique_id")
            if tid:
                index.setdefault(str(tid), []).append(chunk)
        return index

    def lookup_technique(self, tid: str | None) -> dict[str, Any] | None:
        if not tid:
            return None
        if tid in self.mitre_index.index:
            return self.mitre_index.loc[tid].to_dict()
        parent = tid.split(".")[0]
        if parent in self.mitre_index.index:
            return self.mitre_index.loc[parent].to_dict()
        return None

    def _parents_for_tactic(self, tactic: str) -> list[str]:
        hit = self.mitre_lookup[
            self.mitre_lookup["tactics"].astype(str).str.split(", ").apply(lambda ts: tactic in ts)
        ]
        return sorted(set(hit["parent_id"].astype(str)))

    def _rank_chunks(self, chunks: list[dict], query: str, k: int) -> list[dict[str, Any]]:
        scored = []
        seen = set()
        for chunk in chunks:
            cid = chunk.get("id")
            if cid in seen:
                continue
            seen.add(cid)
            text = chunk.get("text", "")
            score = _token_score(query, text)
            meta = chunk.get("metadata", {})
            scored.append(
                {
                    "id": cid,
                    "score": round(score, 3),
                    "text": text[:220].replace("\n", " "),
                    "technique_id": meta.get("technique_id", ""),
                    "source_name": meta.get("source_name") or meta.get("apt_group") or "",
                    "source_type": meta.get("source_type") or meta.get("source") or "",
                    "apt_group": meta.get("apt_group", ""),
                    "report": meta.get("report", ""),
                    "cve_id": meta.get("cve_id", ""),
                    "product": meta.get("product", ""),
                    "cvss": meta.get("cvss", ""),
                }
            )
        scored.sort(key=lambda r: -r["score"])
        return scored[:k]

    def _service_keywords(self, event: dict) -> list[str]:
        kws: list[str] = []
        for service in [event.get("service"), event.get("service_hint")]:
            kws.extend(SERVICE_KEYWORDS.get(str(service or "").lower(), []))
        return list(dict.fromkeys(kws))

    def _cve_mode_for(self, event: dict, parent: str | None, mode: str) -> str | None:
        if mode == "off":
            return None
        if event.get("product") and mode in ("auto", "product"):
            return "product"
        if mode == "product" or parent not in CVE_TECHNIQUES:
            return None
        return "service" if mode in ("auto", "service", "ctid") else None

    def retrieve(
        self,
        event: dict[str, Any],
        k_cve: int = 3,
        k_cti: int = 5,
        fallback: bool = True,
        cve_mode: str | None = None,
    ) -> RetrievalResult:
        tid, tactic = _resolve_ids(event)
        parent = tid.split(".")[0] if tid else None
        mitre = self.lookup_technique(tid) if tid else None
        name = (
            mitre["name"]
            if mitre
            else (f"{tactic} activity" if tactic else "network activity")
        )
        tactics = (
            [tactic]
            if tactic
            else (
                [t for t in str(mitre.get("tactics", "")).split(", ") if t]
                if mitre
                else []
            )
        )

        query = (
            f"{name}: {event.get('behavior', '')} over {event.get('service', '')}/"
            f"{event.get('protocol', '')} port {event.get('port', '')}"
        )

        cti_rows: list[dict[str, Any]] = []
        if parent:
            tech_hits = self._rank_chunks(
                self._cti_by_tech.get(parent, []) + self._proc_by_tech.get(parent, []),
                query,
                k_cti,
            )
            for row in tech_hits:
                level = (
                    "procedure"
                    if str(row.get("source_type", "")).startswith("attack")
                    or "procedure" in str(row.get("source_type", "")).lower()
                    or str(row.get("id", "")).startswith("proc-")
                    else "technique"
                )
                # Prefer labeling ATT&CK procedure chunks correctly.
                if str(row.get("id", "")).startswith("proc-") or row.get("source_type") in {
                    "intrusion-set",
                    "malware",
                    "tool",
                    "campaign",
                }:
                    level = "procedure"
                cti_rows.append({**row, "evidence_level": level})

        if fallback and tactics and len(cti_rows) < k_cti:
            sibling_chunks: list[dict] = []
            for ta in tactics:
                for sib in self._parents_for_tactic(ta):
                    if sib == parent:
                        continue
                    sibling_chunks.extend(self._cti_by_tech.get(sib, []))
                    sibling_chunks.extend(self._proc_by_tech.get(sib, []))
            for row in self._rank_chunks(sibling_chunks, query, k_cti - len(cti_rows)):
                cti_rows.append({**row, "evidence_level": "tactic"})

        # Deduplicate by text.
        deduped: list[dict[str, Any]] = []
        seen_text: set[str] = set()
        for row in cti_rows:
            key = row.get("text", "")
            if key in seen_text:
                continue
            seen_text.add(key)
            deduped.append(row)
        cti_rows = deduped[:k_cti]

        mode = self._cve_mode_for(event, parent, cve_mode or CVE_MODE)
        cve_rows: list[dict[str, Any]] = []
        if mode and self.cve_chunks:
            kws = self._service_keywords(event)
            product = str(event.get("product") or "")
            candidates = []
            for chunk in self.cve_chunks:
                text = chunk.get("text", "")
                meta = chunk.get("metadata", {})
                if mode == "product" and product and product.lower() not in text.lower():
                    continue
                if mode == "service" and kws and not any(k.lower() in text.lower() for k in kws):
                    continue
                candidates.append(chunk)
            cve_rows = self._rank_chunks(candidates or self.cve_chunks, query, k_cve)

        return RetrievalResult(
            event=event,
            mitre=mitre,
            tactics=tactics,
            cve_mode=mode,
            cve=cve_rows,
            cti=cti_rows,
        )
