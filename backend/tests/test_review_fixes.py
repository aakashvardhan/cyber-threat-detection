"""Fixes for the review findings on #23 (SJSU-133)."""
import numpy as np
import pytest
from fastapi.testclient import TestClient

from app.detectors import HeuristicDetector, load_detector
from app.explain import Redactor
from app.incidents import label_probs
from app.main import create_app
from app.replay_data import ReplayData
from conftest import API_KEY


def test_auto_mode_falls_back_when_the_predictions_file_is_broken(make_settings, tmp_path):
    broken = tmp_path / "broken.parquet"
    broken.write_bytes(b"not a parquet file")
    settings = make_settings(primary_model="auto", primary_predictions=broken)
    detector = load_detector(settings, ReplayData.load(settings.replay_file))
    assert isinstance(detector, HeuristicDetector)


def test_precomputed_mode_still_reports_a_broken_file(make_settings, tmp_path):
    broken = tmp_path / "broken.parquet"
    broken.write_bytes(b"not a parquet file")
    settings = make_settings(primary_predictions=broken)
    with pytest.raises(Exception):
        load_detector(settings, ReplayData.load(settings.replay_file))


def test_all_zero_label_rows_are_no_prediction():
    probs = np.array([[0.0, 0.0], [0.2, 0.7]])
    assert label_probs(["T1046", "T1595"], probs, 0) == {}
    assert label_probs(["T1046", "T1595"], probs, 1) == {"T1046": 0.2, "T1595": 0.7}
    assert label_probs([], None, 0) == {}


def test_redactor_hides_every_ipv4_and_restores_it():
    r = Redactor(["143.88.6.11"], enabled=True)
    text = "143.88.6.11 matches IOC 45.33.32.156 seen in CTI; version 1.2.3 and 10.0.0.1.5 stay"
    hidden = r.hide(text)
    assert "143.88.6.11" not in hidden and "45.33.32.156" not in hidden
    assert "host-A" in hidden and "host-B" in hidden and "1.2.3" in hidden
    assert r.reveal(hidden) == text


def test_api_key_is_checked(make_settings):
    with TestClient(create_app(make_settings())) as client:
        assert client.get("/incidents").status_code == 401
        assert client.get("/incidents", headers={"X-API-Key": API_KEY + "x"}).status_code == 401
        assert client.get("/incidents", headers={"X-API-Key": API_KEY}).status_code == 200
