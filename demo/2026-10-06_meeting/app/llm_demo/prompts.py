"""Load the private prompt configuration and assemble prompts from it.

The prompt wording and the few-shot examples are NOT stored in this repository. They live in a JSON
document supplied at run time, looked up in this order:

1. Streamlit secret or environment variable ``GEMMA_PROMPT_CONFIG`` (the JSON text),
2. file named by the environment variable ``GEMMA_PROMPT_CONFIG_FILE``,
3. ``app/.private/prompt_config.json`` (gitignored, for local runs).

Schema (``version`` 1):

    system            system message
    joiner            text placed between prompt parts
    example_template  one few-shot example; placeholders {n}, {event}, {answer}
    target_template   the event to classify; placeholder {event}
    draws             {"<draw>": [{"event": <event record>, "answer": "<gold answer>"}, ...]}
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from app.config import APP_DIR

LOCAL_FILE = APP_DIR / ".private" / "prompt_config.json"
REQUIRED = ("system", "joiner", "example_template", "target_template", "draws")


class PromptConfigError(ValueError):
    pass


def _parse(text) -> dict:
    cfg = json.loads(text) if isinstance(text, str) else json.loads(json.dumps(dict(text)))
    missing = [k for k in REQUIRED if k not in cfg]
    if missing:
        raise PromptConfigError(f"Prompt configuration is missing: {', '.join(missing)}")
    return cfg


def load_config(secret_value=None) -> dict | None:
    """Return the prompt config, or None when none is configured. ``secret_value`` is st.secrets' entry."""
    if secret_value:
        return _parse(secret_value)
    if os.environ.get("GEMMA_PROMPT_CONFIG"):
        return _parse(os.environ["GEMMA_PROMPT_CONFIG"])
    path = Path(os.environ.get("GEMMA_PROMPT_CONFIG_FILE") or LOCAL_FILE)
    return _parse(path.read_text(encoding="utf-8")) if path.exists() else None


def build_prompt(cfg: dict, draw: int | None, record: dict) -> str:
    """Zero-shot when ``draw`` is None, else few-shot with that draw's examples."""
    parts = []
    for n, ex in enumerate(cfg["draws"][str(draw)] if draw is not None else [], 1):
        parts.append(cfg["example_template"].replace("{n}", str(n))
                     .replace("{event}", json.dumps(ex["event"], indent=2)).replace("{answer}", ex["answer"]))
    parts.append(cfg["target_template"].replace("{event}", json.dumps(record, indent=2)))
    return cfg["joiner"].join(parts)


def example_counts(cfg: dict, draw: int | None) -> tuple[int, int]:
    """(total examples, attack examples) for a draw, read from the gold answers."""
    if draw is None:
        return 0, 0
    answers = [json.loads(ex["answer"]) for ex in cfg["draws"][str(draw)]]
    return len(answers), sum(a.get("label") == "attack" for a in answers)
