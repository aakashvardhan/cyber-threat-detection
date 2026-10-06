import numpy as np
import pandas as pd

from baseline_llm import first_mitre, metrics, pick_examples
from edge_serializer import parse_answer


def test_parse_answer():
    assert parse_answer('{"label": "Attack", "mitre": "T1595.001"}') == (1, "T1595.001")
    assert parse_answer('{"label": "normal", "mitre": "T1046"}') == (0, None)   # normal drops mitre
    assert parse_answer("not json") == (None, None)


def test_metrics():
    p = pd.DataFrame(dict(
        y=[1, 1, 0, 0],
        pred=[1, None, 1, 0],          # unparseable answer counts as "attack"
        technique=["T1595.001", None, None, None],
        true_techniques=[["T1595"], ["T1046"], [], []]))
    m = metrics(p, 0.1)
    assert (m.recall, m.fpr, m.unusable) == (1.0, 0.5, 1)
    assert m.technique_acc == 1.0                       # sub-technique matched on parent ID
    assert abs(m.precision_at_prevalence - 0.1 / 0.55) < 1e-4  # 0.1 / (0.1 + 0.45)


def test_pick_examples():
    pool = pd.DataFrame(dict(
        binary_target=[1] * 6 + [0] * 6,
        mitre_targets=[np.array(["T1"])] * 4 + [np.array(["T2"]), None] + [None] * 6))
    ex = pick_examples(pool, 3, 0)
    assert sorted(int(r.binary_target) for r in ex) == [0, 0, 0, 1, 1, 1]
    assert all(first_mitre(r.mitre_targets) in ("T1", "T2") for r in ex if r.binary_target)   # no technique-less attacks
    assert len({r.name for r in ex}) == 6                                                    # no duplicate rows
    assert [r.name for r in ex] == [r.name for r in pick_examples(pool, 3, 0)]              # reproducible
    assert [r.name for r in ex] != [r.name for r in pick_examples(pool, 3, 1)]              # seed changes the draw
