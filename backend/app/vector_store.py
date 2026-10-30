"""Vector retrieval from the RAG notebook (notebooks/RAG/rag.ipynb, sections 4-5 and 7).

Chroma collections, cosine distance, sentence-transformers embeddings (all-MiniLM-L6-v2 by default):
  cti         CTI-HAL report spans (cti_chunks.jsonl)
  procedures  ATT&CK procedure examples (procedure_chunks.jsonl, or built from enterprise-attack.json)
  cve         CVE records (cve_chunks.jsonl)
  techniques  one document per ATT&CK technique, for the behaviour check

retrieve(event) follows the notebook: MITRE lookup -> CVE search (exploit-type techniques, service keywords)
-> CTI chunks of the technique -> procedure examples of the technique -> CTI chunks of other techniques in the
same tactic. The index is built once into CHROMA_DIR and reused; it is rebuilt when a source file changes.

Optional: without chromadb / sentence-transformers, or without the model, the backend keeps the token-overlap
retriever in app/knowledge.py.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from collections import Counter
from pathlib import Path

log = logging.getLogger(__name__)

CVE_TECHNIQUES = {"T1190", "T1210", "T1203", "T1211", "T1212", "T1068"}
SERVICE_KEYWORDS = {"http": ["HTTP"], "ssl": ["TLS", "SSL"], "ssh": ["SSH"], "dns": ["DNS"],
                    "smb": ["SMB"], "rdp": ["RDP", "Remote Desktop"], "ftp": ["FTP"]}


def is_lfs_pointer(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(40).startswith(b"version https://git-lfs")
    except OSError:
        return False


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists() or is_lfs_pointer(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def procedures_from_stix(stix_path: Path) -> list[dict]:
    """ATT&CK procedure examples: 'uses' relationships (group / software / campaign -> technique) with a description."""
    objs = {o["id"]: o for o in json.loads(Path(stix_path).read_text(encoding="utf-8"))["objects"]}

    def ext(o):
        return next((r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), {})

    chunks = []
    for rel in objs.values():
        if rel["type"] != "relationship" or rel.get("relationship_type") != "uses" or not rel.get("description"):
            continue
        src, dst = objs.get(rel["source_ref"]), objs.get(rel["target_ref"])
        if not src or not dst or dst["type"] != "attack-pattern" or dst.get("revoked") or dst.get("x_mitre_deprecated"):
            continue
        tid = ext(dst).get("external_id")
        if not tid:
            continue
        text = re.sub(r"\(Citation:[^)]*\)", "", rel["description"])
        text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text).strip()
        if len(text.split()) < 4:
            continue
        chunks.append({"id": f"proc-{rel['id'].split('--')[1]}", "text": text, "metadata": {
            "source": "attack-procedure", "technique_id": tid, "technique_ids": sorted({tid, tid.split(".")[0]}),
            "source_name": src.get("name", ""), "source_type": {"intrusion-set": "group", "campaign": "campaign"}.get(src["type"], "software"),
            "source_attack_id": ext(src).get("external_id", ""), "url": ext(src).get("url", "")}})
    return chunks


def _meta(meta: dict) -> dict:
    out = {k: v for k, v in meta.items() if isinstance(v, (str, int, float, bool))}
    ids = meta.get("technique_ids") or ([meta["technique_id"]] if meta.get("technique_id") else [])
    ids = sorted({str(t).split(".")[0] for t in ([ids] if isinstance(ids, str) else ids) if t})
    if ids:
        out["technique_ids"] = ids
    return out or {"source": "unknown"}


class VectorStore:
    def __init__(self, client, embed, model_name: str, counts: dict[str, Counter]):
        self.client, self.embed, self.model_name = client, embed, model_name
        self.cols = {c.name: c for c in client.list_collections()}
        self.counts = counts                     # collection -> parent technique -> chunk count
        self.has_techniques = "techniques" in self.cols

    # ----- building -----
    @classmethod
    def load(cls, knowledge_dir: Path | None, chroma_dir: Path, model: str, stix_path: Path | None = None,
             technique_docs: dict | None = None) -> "VectorStore | None":
        try:
            import chromadb
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            log.info("Vector retrieval off (%s); using token overlap", exc)
            return None
        try:
            encoder = SentenceTransformer(model, device="cpu")
        except Exception as exc:  # noqa: BLE001 - model not downloaded / offline
            log.warning("Vector retrieval off: cannot load embedding model %s (%s)", model, exc)
            return None

        def embed(texts: list[str]) -> list[list[float]]:
            return encoder.encode(texts, batch_size=128, normalize_embeddings=True, show_progress_bar=False).tolist()

        kdir = Path(knowledge_dir) if knowledge_dir else None
        sources: dict[str, list[dict]] = {}
        if kdir is not None:
            for name, filename in (("cti", "cti_chunks.jsonl"), ("procedures", "procedure_chunks.jsonl"), ("cve", "cve_chunks.jsonl")):
                sources[name] = read_jsonl(kdir / filename)
        if not sources.get("procedures") and stix_path is not None and Path(stix_path).exists():
            sources["procedures"] = procedures_from_stix(stix_path)
        if technique_docs:
            sources["techniques"] = [{"id": t, "text": f"{d['name']}. {d['text'][:1500]} {d['network_text'][:1500]}",
                                      "metadata": {"technique_ids": [t], "name": d["name"]}} for t, d in technique_docs.items()]

        chroma_dir.mkdir(parents=True, exist_ok=True)
        return cls.from_sources(chromadb.PersistentClient(path=str(chroma_dir)), embed, model, sources)

    @classmethod
    def from_sources(cls, client, embed, model: str, sources: dict[str, list[dict]]) -> "VectorStore":
        """Create or reuse one collection per source; a collection is rebuilt when its chunk IDs or the model change."""
        existing = {c.name: c for c in client.list_collections()}
        counts: dict[str, Counter] = {}
        for name, chunks in sources.items():
            if not chunks:
                continue
            signature = hashlib.sha1((model + "|" + "|".join(c["id"] for c in chunks)).encode()).hexdigest()
            col = existing.get(name)
            if col is None or (col.metadata or {}).get("signature") != signature:
                if col is not None:
                    client.delete_collection(name)
                started = time.time()
                log.info("Building vector index '%s' (%d chunks); this runs once", name, len(chunks))
                col = client.create_collection(name, metadata={"hnsw:space": "cosine", "signature": signature, "embed_model": model})
                seen = set()
                unique = [c for c in chunks if not (c["id"] in seen or seen.add(c["id"]))]
                for i in range(0, len(unique), 1000):
                    part = unique[i:i + 1000]
                    col.add(ids=[c["id"] for c in part], documents=[c["text"] for c in part],
                            metadatas=[_meta(c.get("metadata", {})) for c in part], embeddings=embed([c["text"] for c in part]))
                log.info("Built '%s' in %.0fs", name, time.time() - started)
            counts[name] = Counter(t for c in chunks for t in _meta(c.get("metadata", {})).get("technique_ids", []))
        for name in set(existing) - {n for n, c in sources.items() if c}:   # source file removed
            client.delete_collection(name)
        return cls(client, embed, model, counts)

    # ----- search -----
    def search(self, collection: str, query: str, k: int, where=None, where_document=None,
               min_score: float | None = None) -> list[dict]:
        col = self.cols.get(collection)
        if col is None or k <= 0:
            return []
        res = col.query(query_embeddings=self.embed([query]), n_results=k, where=where, where_document=where_document)
        hits = [{"id": i, "text": d, "score": round(1 - dist, 3), "metadata": m or {}}
                for i, d, dist, m in zip(res["ids"][0], res["documents"][0], res["distances"][0], res["metadatas"][0])]
        return [h for h in hits if min_score is None or h["score"] >= min_score]

    def searched(self, collection: str, technique_ids: list[str]) -> int:
        counts = self.counts.get(collection, Counter())
        return sum(counts.get(t, 0) for t in technique_ids)

    def techniques_for(self, text: str, k: int = 10) -> list[str]:
        return [h["metadata"].get("technique_ids", [h["id"]])[0] for h in self.search("techniques", text, k)]

    @staticmethod
    def _any(values: list[str]) -> dict:
        conds = [{"technique_ids": {"$contains": v}} for v in values]
        return conds[0] if len(conds) == 1 else {"$or": conds}

    def retrieve(self, event: dict, siblings: list[str], k_cti: int = 5, k_cve: int = 2, min_score: float = 0.0) -> dict:
        """event: technique_id, technique_name, service, protocol, port, behavior. siblings: other techniques in the tactic."""
        parent = (event.get("technique_id") or "").split(".")[0] or None
        name = event.get("technique_name") or "network activity"
        query = (f"{name}: {event.get('behavior', '')} over {event.get('service') or 'unknown'}/"
                 f"{event.get('protocol') or 'unknown'} port {event.get('port') or 'unknown'}")
        sources, hits = [], []
        if parent:
            found = self.search("cti", query, k_cti, where={"technique_ids": {"$contains": parent}}, min_score=min_score)
            hits += [dict(h, source="cti", level="technique") for h in found]
            sources.append({"source": "cti", "searched": self.searched("cti", [parent]), "returned": len(found)})
            if len(hits) < k_cti:
                found = self.search("procedures", query, k_cti - len(hits), where={"technique_ids": {"$contains": parent}}, min_score=min_score)
                hits += [dict(h, source="procedure", level="procedure") for h in found]
                sources.append({"source": "procedure", "searched": self.searched("procedures", [parent]), "returned": len(found)})
        fallback = False
        if siblings and len(hits) < k_cti:
            found = self.search("cti", query, k_cti - len(hits), where=self._any(siblings), min_score=min_score)
            hits += [dict(h, source="cti", level="tactic") for h in found]
            fallback = bool(found)
            for s in sources:
                if s["source"] == "cti":
                    s["searched"] += self.searched("cti", siblings)
                    s["returned"] += len(found)
                    break
            else:
                sources.append({"source": "cti", "searched": self.searched("cti", siblings), "returned": len(found)})
        if not any(s["source"] == "procedure" for s in sources):
            sources.append({"source": "procedure", "returned": 0, "skipped": True})

        cve_query = None
        if parent in CVE_TECHNIQUES and "cve" in self.cols:
            kws = SERVICE_KEYWORDS.get(str(event.get("service") or "").lower(), [])
            wd = None if not kws else ({"$contains": kws[0]} if len(kws) == 1 else {"$or": [{"$contains": k} for k in kws]})
            cve_query = " ".join(str(x) for x in [name, event.get("service"), event.get("behavior"), "vulnerability"] if x)
            found = self.search("cve", cve_query, k_cve, where_document=wd, min_score=min_score)
            hits += [dict(h, source="cve", level="cve") for h in found]
            sources.append({"source": "cve", "searched": self.cols["cve"].count(), "returned": len(found)})
        else:
            sources.append({"source": "cve", "returned": 0, "skipped": True})

        evidence, seen = [], set()
        for h in hits:
            if h["text"] in seen:
                continue
            seen.add(h["text"])
            m = h["metadata"]
            evidence.append({
                "source": h["source"], "level": h["level"],
                "ref": m.get("source_attack_id") or m.get("cve_id") or m.get("report") or h["id"],
                "title": (m.get("cve_id") or m.get("source_name") or
                          " ".join(x for x in [m.get("apt_group"), m.get("report")] if x) or h["source"].upper()),
                "text": re.sub(r"\s+", " ", h["text"]).strip()[:400], "score": h["score"], "url": m.get("url") or None,
            })
        return {"evidence": evidence, "sources": sources, "query": query, "cve_query": cve_query,
                "fallback_to_tactic": fallback}

    def stats(self) -> dict:
        return {name: col.count() for name, col in self.cols.items()}
