"""Bootstrap MITRE ATT&CK artifacts into app/data/rag for self-contained RAG."""
from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

# Allow `python -m app.rag.bootstrap` from project root or app folder.
APP_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = APP_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.rag.attack_parse import parse_attack, parse_procedures, write_jsonl  # noqa: E402
from app.rag.paths import (  # noqa: E402
    ATTACK_JSON,
    ATTACK_JSON_URL,
    MITRE_LOOKUP_CSV,
    MITRE_MITIGATIONS_CSV,
    PROCEDURE_CHUNKS_JSONL,
    PROCESSED_DIR,
    RAG_DIR,
)


def download_attack_json(force: bool = False) -> Path:
    RAG_DIR.mkdir(parents=True, exist_ok=True)
    if ATTACK_JSON.exists() and not force:
        print("Using existing", ATTACK_JSON)
        return ATTACK_JSON
    print("Downloading MITRE ATT&CK enterprise-attack.json ...")
    urllib.request.urlretrieve(ATTACK_JSON_URL, ATTACK_JSON)
    print("Saved", ATTACK_JSON, f"({ATTACK_JSON.stat().st_size / 1e6:.1f} MB)")
    return ATTACK_JSON


def build_processed(force: bool = False) -> None:
    download_attack_json(force=force)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    if force or not MITRE_LOOKUP_CSV.exists():
        lookup, mitigations = parse_attack(ATTACK_JSON)
        lookup.to_csv(MITRE_LOOKUP_CSV, index=False)
        mitigations.to_csv(MITRE_MITIGATIONS_CSV, index=False)
        print(f"Wrote {MITRE_LOOKUP_CSV.name}: {len(lookup)} techniques")
    else:
        print("Skipping mitre_lookup (exists)")

    if force or not PROCEDURE_CHUNKS_JSONL.exists():
        chunks = parse_procedures(ATTACK_JSON)
        write_jsonl(chunks, PROCEDURE_CHUNKS_JSONL)
        print(f"Wrote {PROCEDURE_CHUNKS_JSONL.name}: {len(chunks)} procedure chunks")
    else:
        print("Skipping procedure_chunks (exists)")


def ensure_rag_ready() -> bool:
    """Ensure required lightweight RAG artifacts exist; build if missing."""
    needed = [MITRE_LOOKUP_CSV, PROCEDURE_CHUNKS_JSONL]
    if all(p.exists() for p in needed):
        return True
    build_processed(force=False)
    return all(p.exists() for p in needed)


if __name__ == "__main__":
    force = "--force" in sys.argv
    build_processed(force=force)
    print("RAG bootstrap complete.")
