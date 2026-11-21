"""Evaluation LLM cache: the same prompt is answered from disk, a changed prompt calls the LLM again."""
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from llm_cache import LLMCache  # noqa: E402


def test_cache_hits_survive_a_new_process(tmp_path):
    path = tmp_path / "cache.sqlite"
    calls = []

    def llm(answer):
        calls.append(answer)
        return answer

    first = LLMCache(path)
    assert first.cached("judge", "m", "sys", "prompt 1", lambda: llm({"claims": [1]})) == {"claims": [1]}
    assert first.cached("judge", "m", "sys", "prompt 1", lambda: llm({"claims": [2]})) == {"claims": [1]}
    second = LLMCache(path)                                              # a rerun of the evaluation
    assert second.cached("judge", "m", "sys", "prompt 1", lambda: llm({"claims": [3]})) == {"claims": [1]}
    assert second.cached("judge", "m", "sys", "prompt 2", lambda: llm({"claims": [4]})) == {"claims": [4]}
    assert second.cached("judge", "other-model", "sys", "prompt 1", lambda: llm("x")) == "x"
    assert calls == [{"claims": [1]}, {"claims": [4]}, "x"]
    assert second.stats() == {"judge": {"hits": 1, "calls": 2}}


def test_failed_calls_are_not_stored(tmp_path):
    cache = LLMCache(tmp_path / "c.sqlite")

    def fail():
        raise TimeoutError

    try:
        cache.cached("generator", "m", "s", "p", fail)
    except TimeoutError:
        pass
    assert cache.cached("generator", "m", "s", "p", lambda: "ok") == "ok"


def test_disabled_cache_always_calls(tmp_path):
    cache = LLMCache(None)
    assert [cache.cached("g", "m", "s", "p", lambda i=i: i) for i in range(2)] == [0, 1]


def test_threads_share_one_cache(tmp_path):
    cache = LLMCache(tmp_path / "c.sqlite")
    with ThreadPoolExecutor(8) as pool:
        out = list(pool.map(lambda i: cache.cached("judge", "m", "s", f"p{i % 4}", lambda: i % 4), range(40)))
    assert out == [i % 4 for i in range(40)]
