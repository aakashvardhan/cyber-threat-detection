"""Disk cache for evaluation LLM calls (generator and judge), so a rerun only pays for what changed.

The key is a hash of (purpose, model, system prompt, user prompt, sampling settings). Same input -> the stored
answer, no API call; a changed input (e.g. the reranker reorders the evidence) -> a new call. Only successful
answers are stored. One SQLite file, safe for the evaluation's worker threads.

    cache = LLMCache(".eval_cache/llm_cache.sqlite")
    answer = cache.cached("judge", model, system, user, lambda: call_llm(...))
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path


class LLMCache:
    def __init__(self, path: str | Path | None):
        self.enabled = path is not None
        self.lock = threading.Lock()
        self.hits = {}
        self.misses = {}
        if self.enabled:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            self.db = sqlite3.connect(str(path), check_same_thread=False)
            self.db.execute("CREATE TABLE IF NOT EXISTS calls (key TEXT PRIMARY KEY, purpose TEXT, model TEXT, "
                            "answer TEXT, created REAL)")
            self.db.commit()

    @staticmethod
    def key(purpose: str, model: str, system: str, user: str, params: dict | None = None) -> str:
        raw = json.dumps([purpose, model, system, user, params or {}], ensure_ascii=False, sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()

    def get(self, key: str):
        if not self.enabled:
            return None
        with self.lock:
            row = self.db.execute("SELECT answer FROM calls WHERE key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, key: str, purpose: str, model: str, answer) -> None:
        if not self.enabled:
            return
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO calls VALUES (?, ?, ?, ?, ?)",
                            (key, purpose, model, json.dumps(answer, ensure_ascii=False), time.time()))
            self.db.commit()

    def cached(self, purpose: str, model: str, system: str, user: str, call, params: dict | None = None):
        k = self.key(purpose, model, system, user, params)
        answer = self.get(k)
        if answer is not None:
            with self.lock:
                self.hits[purpose] = self.hits.get(purpose, 0) + 1
            return answer
        answer = call()
        with self.lock:
            self.misses[purpose] = self.misses.get(purpose, 0) + 1
        self.put(k, purpose, model, answer)
        return answer

    def stats(self) -> dict:
        return {p: {"hits": self.hits.get(p, 0), "calls": self.misses.get(p, 0)}
                for p in sorted(set(self.hits) | set(self.misses))}
