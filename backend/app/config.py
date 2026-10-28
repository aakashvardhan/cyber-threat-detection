"""Settings read from environment variables (see backend/.env.example).

Every artifact is optional: the backend picks the best source that exists and
reports which one it used, so it runs before the final models are delivered.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO_DATA = REPO_ROOT / "demo" / "2026-10-06_meeting" / "app" / "data"
BUNDLED_DATA = Path(__file__).resolve().parent / "data"


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def _flag(name: str, default: bool) -> bool:
    value = _env(name)
    return default if value is None else value.strip().lower() in {"1", "true", "yes", "on"}


def _first_existing(*paths: Path | None) -> Path | None:
    for path in paths:
        if path is not None and path.exists():
            return path
    return None


@dataclass
class Settings:
    api_key: str = "dev-key"
    data_dir: Path = REPO_ROOT / "backend" / "data"

    # replay traffic: Sai's processed test edges, else the Oct 6 demo test split
    replay_file: Path | None = None
    # primary model: "auto" | "graphsage" | "precomputed" | "heuristic"
    primary_model: str = "auto"
    primary_model_name: str | None = None
    threshold: float | None = None
    model_checkpoint: Path | None = None
    preprocessing_file: Path | None = None
    primary_predictions: Path | None = None   # e.g. the decision model (model_5) exported per edge
    model_outputs: Path | None = None         # Models 1-5 per edge, for the Research tab
    metrics_file: Path | None = None
    knowledge_dir: Path | None = None
    # retrieval: "auto" uses vector search when chromadb + sentence-transformers + the model are available
    rag_mode: str = "auto"                    # "auto" | "vector" | "token"
    embed_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    chroma_dir: Path | None = None
    attack_stix: Path | None = None           # enterprise-attack.json: technique documents + procedure examples
    behavior_check: bool = True

    # explanations
    llm_provider: str = "none"                # "groq" | "local" | "none"
    llm_base_url: str | None = None
    llm_model: str | None = None
    llm_api_key: str | None = None
    llm_timeout_s: float = 60.0
    llm_max_tokens: int = 2000
    redact_ips: bool = False

    # behaviour
    incident_gap_minutes: int = 30
    related_window_minutes: int = 60
    retrieval_top_k: int = 5
    retrieval_min_score: float = 0.05
    cors_origins: list[str] = field(default_factory=lambda: ["http://localhost:5173", "http://localhost:3000"])

    @classmethod
    def from_env(cls) -> "Settings":
        data_dir = Path(_env("DATA_DIR", str(REPO_ROOT / "backend" / "data")))

        def path(name: str, *defaults: Path) -> Path | None:
            explicit = _env(name)
            return Path(explicit) if explicit else _first_existing(*defaults)

        groq_key = _env("GROQ_API_KEY")
        provider = _env("LLM_PROVIDER", "groq" if groq_key else "none").lower()
        if provider == "groq":
            base_url = _env("LLM_BASE_URL", "https://api.groq.com/openai/v1")
            model = _env("LLM_MODEL", _env("GROQ_MODEL", "openai/gpt-oss-20b"))
            api_key = _env("LLM_API_KEY", groq_key)
        else:
            base_url = _env("LLM_BASE_URL", "http://localhost:11434/v1")
            model = _env("LLM_MODEL")
            api_key = _env("LLM_API_KEY")

        threshold = _env("THRESHOLD")
        return cls(
            api_key=_env("API_KEY", "dev-key"),
            data_dir=data_dir,
            replay_file=path("REPLAY_FILE", data_dir / "test_edges.parquet",
                             DEMO_DATA / "test_edges_5min_enriched.parquet"),
            primary_model=_env("PRIMARY_MODEL", "auto").lower(),
            primary_model_name=_env("PRIMARY_MODEL_NAME"),
            threshold=float(threshold) if threshold else None,
            model_checkpoint=path("MODEL_CHECKPOINT", data_dir / "graphsage_best_model.pt",
                                  data_dir / "graphsage_exp1_best_model.pt"),
            preprocessing_file=path("PREPROCESSING_FILE", data_dir / "preprocessing_objects.joblib"),
            primary_predictions=path("PRIMARY_PREDICTIONS", data_dir / "primary_predictions.parquet"),
            model_outputs=path("MODEL_OUTPUTS", data_dir / "model_outputs.jsonl"),
            metrics_file=path("METRICS_FILE", data_dir / "metrics.json", BUNDLED_DATA / "metrics.default.json"),
            knowledge_dir=path("KNOWLEDGE_DIR", data_dir / "knowledge", DEMO_DATA / "rag" / "processed"),
            rag_mode=_env("RAG_MODE", "auto").lower(),
            embed_model=_env("EMBED_MODEL", "sentence-transformers/all-MiniLM-L6-v2"),
            chroma_dir=Path(_env("CHROMA_DIR", str(data_dir / "chroma_db"))),
            attack_stix=path("ATTACK_STIX", data_dir / "knowledge" / "enterprise-attack.json",
                             DEMO_DATA / "rag" / "enterprise-attack.json"),
            behavior_check=_flag("BEHAVIOR_CHECK", True),
            llm_provider=provider,
            llm_base_url=base_url,
            llm_model=model,
            llm_api_key=api_key,
            llm_timeout_s=float(_env("LLM_TIMEOUT_S", "60")),
            llm_max_tokens=int(_env("LLM_MAX_TOKENS", "2000")),
            redact_ips=_flag("REDACT_IPS", False),
            incident_gap_minutes=int(_env("INCIDENT_GAP_MINUTES", "30")),
            retrieval_top_k=int(_env("RETRIEVAL_TOP_K", "5")),
            retrieval_min_score=float(_env("RETRIEVAL_MIN_SCORE", "0.05")),
            cors_origins=[o.strip() for o in _env("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",") if o.strip()],
        )
