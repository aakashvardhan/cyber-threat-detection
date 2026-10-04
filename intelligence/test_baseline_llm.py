import numpy as np
import pandas as pd

from baseline_llm import auc, metrics, parse


def test_parse():
    assert parse('{"label": "Attack", "attack_probability": 0.9, "technique": "T1595"}') == (1, 0.9, "T1595")
    assert parse('{"label": "normal", "technique": ""}') == (0, 0.0, None)   # missing prob -> from label
    assert parse('{"label": "attack", "attack_probability": 7}') == (1, 1.0, None)   # clipped
    assert parse("not json") == (None, 0.5, None)
    assert parse('{"label": "maybe"}') == (None, 0.5, None)


def test_auc():
    assert auc([0, 0, 1, 1], [0.1, 0.2, 0.8, 0.9]) == 1.0
    assert auc([0, 0, 1, 1], [0.9, 0.8, 0.2, 0.1]) == 0.0
    assert auc([0, 1, 0, 1], [0.5, 0.5, 0.5, 0.5]) == 0.5
    assert np.isnan(auc([1, 1], [0.1, 0.2]))


def test_metrics():
    p = pd.DataFrame(dict(
        source_dataset=["A"] * 4,
        y=[1, 1, 0, 0],
        pred=[1, None, 1, 0],          # unusable answer counts as "normal"
        p_attack=[0.9, 0.5, 0.6, 0.1],
        technique=["T1595.001", None, None, None],
        tech_mode=["T1595", "T1046", None, None]))
    m = metrics(p, {"A": 0.1, "ALL": 0.1}).loc["A"]
    assert (m.recall, m.fpr, m.unusable) == (0.5, 0.5, 1)
    assert m.technique_acc == 1.0                       # sub-technique matched on parent ID
    assert abs(m.precision_at_prevalence - 0.1) < 1e-4  # 0.05 / (0.05 + 0.45)
