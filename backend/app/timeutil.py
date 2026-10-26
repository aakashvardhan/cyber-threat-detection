"""Timestamps: stored as naive UTC, sent as ISO 8601 with a trailing Z."""
from __future__ import annotations

from datetime import datetime, timezone

import pandas as pd


def to_naive_utc(value) -> pd.Timestamp:
    ts = pd.Timestamp(value)
    if ts.tzinfo is not None:
        ts = ts.tz_convert("UTC").tz_localize(None)
    return ts


def iso(value) -> str | None:
    if value is None:
        return None
    return to_naive_utc(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
