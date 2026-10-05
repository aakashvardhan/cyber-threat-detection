"""Resolve Groq credentials from .env or Streamlit secrets."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

APP_DIR = Path(__file__).resolve().parent.parent
DEFAULT_GROQ_MODEL = "openai/gpt-oss-20b"


def _load_dotenv() -> None:
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv(APP_DIR / ".env", override=False)
    load_dotenv(APP_DIR.parent / ".env", override=False)


def _from_streamlit_secrets(key: str) -> str | None:
    """Read from Streamlit secrets if a secrets.toml exists; never crash if missing."""
    try:
        import streamlit as st
    except ImportError:
        return None

    try:
        secrets: Any = st.secrets
        # Flat: GROQ_API_KEY = "..."
        if key in secrets:
            value = secrets.get(key)
            if value:
                return str(value).strip()

        # Nested: [groq] api_key = "..."
        groq_section = secrets.get("groq", {})
        if hasattr(groq_section, "get") or isinstance(groq_section, dict):
            nested_key = "api_key" if key == "GROQ_API_KEY" else "model"
            value = groq_section.get(nested_key) or groq_section.get(key)
            if value:
                return str(value).strip()
    except FileNotFoundError:
        return None
    except Exception:
        # Missing secrets.toml, parse errors, or StreamlitAPIException, etc.
        return None
    return None


def _is_placeholder(value: str | None) -> bool:
    if not value:
        return True
    lowered = value.strip().lower()
    return lowered.startswith("your_groq_api_key") or lowered in {"", "none", "null"}


def get_groq_api_key(explicit: str | None = None) -> str | None:
    """Priority: explicit arg -> env/.env -> Streamlit secrets."""
    _load_dotenv()
    # Prefer env first so missing secrets.toml never blocks .env usage.
    for value in (
        (explicit or "").strip(),
        (os.environ.get("GROQ_API_KEY") or "").strip(),
    ):
        if not _is_placeholder(value):
            return value

    secret_value = _from_streamlit_secrets("GROQ_API_KEY") or ""
    if not _is_placeholder(secret_value):
        return secret_value
    return None


def get_groq_model(explicit: str | None = None) -> str:
    """Priority: explicit arg -> env/.env -> Streamlit secrets -> default."""
    _load_dotenv()
    for value in (
        (explicit or "").strip(),
        (os.environ.get("GROQ_MODEL") or "").strip(),
    ):
        if value and value.lower() not in {"none", "null"}:
            return value

    secret_value = _from_streamlit_secrets("GROQ_MODEL") or ""
    if secret_value and secret_value.lower() not in {"none", "null"}:
        return secret_value
    return DEFAULT_GROQ_MODEL
