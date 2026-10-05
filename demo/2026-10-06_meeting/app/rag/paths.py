"""RAG paths and settings under app/data/rag."""
from __future__ import annotations

import os
from pathlib import Path

from app.config import DATA_DIR

RAG_DIR = DATA_DIR / "rag"
PROCESSED_DIR = RAG_DIR / "processed"
CHROMA_DIR = RAG_DIR / "chroma_db"
ATTACK_JSON = RAG_DIR / "enterprise-attack.json"
MITRE_LOOKUP_CSV = PROCESSED_DIR / "mitre_lookup.csv"
MITRE_MITIGATIONS_CSV = PROCESSED_DIR / "mitre_mitigations.csv"
PROCEDURE_CHUNKS_JSONL = PROCESSED_DIR / "procedure_chunks.jsonl"
CVE_CHUNKS_JSONL = PROCESSED_DIR / "cve_chunks.jsonl"
CTI_CHUNKS_JSONL = PROCESSED_DIR / "cti_chunks.jsonl"

ATTACK_JSON_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)
EMBED_MODEL = os.environ.get("RAG_EMBED_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
CVE_MODE = os.environ.get("RAG_CVE_MODE", "auto")
CVE_TECHNIQUES = {"T1190", "T1210", "T1203", "T1211", "T1212", "T1068"}
SERVICE_KEYWORDS = {
    "http": ["HTTP"],
    "ssl": ["TLS", "SSL"],
    "ssh": ["SSH"],
    "dns": ["DNS"],
    "smb": ["SMB"],
    "rdp": ["RDP", "Remote Desktop"],
    "ftp": ["FTP"],
}
HOST_ONLY = {"T1204", "T1547", "T1136", "T1059", "T1112", "T1546"}
