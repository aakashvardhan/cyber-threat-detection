"""Run from demo/2026-10-06_meeting:  python -m pytest app/tests -q

Prompt tests use a synthetic config with dummy wording; the real prompts are not in the repository.
"""
import io
import json
import sys
import urllib.error
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.config import LLM_EVAL_DIR  # noqa: E402
from app.llm_demo import live, prompts, replay  # noqa: E402
from app.llm_demo.serializer import parse_answer  # noqa: E402

CFG = {
    "version": 1, "system": "SYS", "joiner": "\n\n---\n\n",
    "example_template": "EXAMPLE {n}\n{event}\nGOLD {answer}",
    "target_template": "TARGET\n{event}\nGO:",
    "draws": {"0": [{"event": {"row_id": i}, "answer": json.dumps({"label": "attack" if i < 3 else "normal", "mitre": None})}
                    for i in range(8)]},
}


@pytest.mark.parametrize("run", list(replay.RUNS))
def test_metrics_match_saved_csv(run):
    prefix, _ = replay.RUNS[run]
    saved = pd.read_csv(LLM_EVAL_DIR / f"{prefix}_{replay.SUFFIX}.metrics.csv", index_col=0).value
    m = replay.run_metrics(run, replay.test_prevalence())
    assert m["recall"] == pytest.approx(saved["recall"], abs=1e-4)
    assert m["fpr"] == pytest.approx(saved["fpr"], abs=1e-4)
    assert m["precision"] == pytest.approx(saved["precision_at_prevalence"], abs=1e-4)
    assert m["technique_acc"] == pytest.approx(saved["technique_acc"], abs=1e-3)


@pytest.mark.parametrize("run", list(replay.RUNS))
def test_saved_replies_parse_to_saved_preds_and_hold_no_reasoning(run):
    for r in replay.load_run(run).values():
        assert parse_answer(r.raw)[0] == r.pred
        assert "<thought>" not in r.raw


def test_prompt_assembly_few_shot_and_zero_shot():
    rec = {"event_id": "e", "row_id": 1, "event": {"traffic_features": {}}}
    few = prompts.build_prompt(CFG, 0, rec)
    assert few.count("EXAMPLE ") == 8 and few.rstrip().endswith("GO:")
    assert few.index("EXAMPLE 8") < few.index("TARGET")
    zero = prompts.build_prompt(CFG, None, rec)
    assert "EXAMPLE" not in zero and zero.startswith("TARGET")
    assert prompts.example_counts(CFG, 0) == (8, 3) and prompts.example_counts(CFG, None) == (0, 0)


def test_template_braces_in_question_are_safe():
    cfg = dict(CFG, target_template='TARGET\n{event}\nAnswer only with {"a": 1}\nA:')
    out = prompts.build_prompt(cfg, None, {"x": 1})
    assert '{"a": 1}' in out and "{event}" not in out


def test_config_loading(monkeypatch, tmp_path):
    monkeypatch.delenv("GEMMA_PROMPT_CONFIG", raising=False)
    monkeypatch.setenv("GEMMA_PROMPT_CONFIG_FILE", str(tmp_path / "missing.json"))
    assert prompts.load_config() is None
    f = tmp_path / "cfg.json"
    f.write_text(json.dumps(CFG))
    monkeypatch.setenv("GEMMA_PROMPT_CONFIG_FILE", str(f))
    assert prompts.load_config()["system"] == "SYS"
    monkeypatch.setenv("GEMMA_PROMPT_CONFIG", json.dumps(dict(CFG, system="ENV")))
    assert prompts.load_config()["system"] == "ENV"
    assert prompts.load_config(json.dumps(dict(CFG, system="SECRET")))["system"] == "SECRET"
    with pytest.raises(prompts.PromptConfigError):
        prompts.load_config(json.dumps({"system": "x"}))


PASTED = json.dumps({
    "event_id": "uwf-test-135951", "row_id": 135951,
    "event": {"window_start": "2025-05-30T16:25:00", "source_ip": "143.88.3.14", "destination_ip": "143.88.3.11",
              "traffic_features": {"connection_count": 65536, "tcp_count": 65536.0}},
    "gnn_detection": {"binary_prediction": {"label": "attack"}},
    "ground_truth": {"label_binary": 1, "label_technique": ["T1595"]}})


def test_custom_event_drops_gnn_and_truth():
    rec, ignored = replay.parse_custom_event(PASTED)
    assert ignored == ["gnn_detection", "ground_truth"]
    p = replay.prompt_for_record(CFG, "Few-shot (draw 0)", rec)
    assert "ground_truth" not in p and "gnn_detection" not in p and "T1595" not in p
    assert '"row_id": 135951' in p


@pytest.mark.parametrize("bad", ["not json", "[1,2]", '{"foo": 1}', '{"event": {"x": 1}}'])
def test_custom_event_rejects_bad_input(bad):
    with pytest.raises(ValueError):
        replay.parse_custom_event(bad)


def test_bare_event_block_is_accepted():
    rec, _ = replay.parse_custom_event('{"traffic_features": {"connection_count": 3}}')
    assert rec["event"]["traffic_features"]["connection_count"] == 3


def test_scrub_removes_key():
    assert "SECRET123" not in live.scrub("bad key SECRET123 here", "SECRET123")


@pytest.mark.parametrize("code,body", [(400, "invalid key SECRET123"), (401, "key SECRET123")])
def test_http_error_does_not_leak_key(monkeypatch, code, body):
    def boom(req, timeout=0):
        raise urllib.error.HTTPError(req.full_url, code, "bad", {}, io.BytesIO(body.encode()))

    monkeypatch.setattr(live.urllib.request, "urlopen", boom)
    with pytest.raises(live.LiveCallError) as e:
        live.ask_gemma("hi", "SECRET123", "SYS")
    assert "SECRET123" not in str(e.value)


def test_missing_key():
    with pytest.raises(live.LiveCallError):
        live.ask_gemma("hi", "", "SYS")
