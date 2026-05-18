"""predict_one behaviour: rules vs ML vs missing model."""
from unittest.mock import MagicMock

import pytest

import app.predictor as pred


def _base_row(**overrides):
    row = {
        "log_id": 1,
        "device": "R1",
        "intf": "Gi0/0",
        "label": "normal",
        "is_device_down": False,
        "is_admin_down": False,
        "status_num": 1,
        "protocol_num": 1,
        "reliability": 255,
        "network_load": 1,
        "rxload": 1,
        "input_errors": 0,
        "link_type": "LAN",
    }
    row.update(overrides)
    return row


def test_predict_device_unreachable():
    label, conf, src = pred.predict_one(_base_row(is_device_down=True))
    assert label == "anomaly" and conf == 1.0 and src == "device_unreachable"


def test_predict_rules_anomaly():
    label, conf, src = pred.predict_one(_base_row(label="anomaly"))
    assert label == "anomaly" and src == "rules"


def test_predict_no_model(monkeypatch):
    monkeypatch.setattr(pred, "model", None)
    label, conf, src = pred.predict_one(_base_row())
    assert label == "normal" and src == "no_model"


def test_predict_isolation_forest_outlier(monkeypatch):
    m = MagicMock()
    m.predict = MagicMock(return_value=[-1])
    monkeypatch.setattr(pred, "model", m)
    label, conf, src = pred.predict_one(_base_row())
    assert label == "anomaly" and src == "isolation_forest"


def test_predict_isolation_forest_inlier(monkeypatch):
    m = MagicMock()
    m.predict = MagicMock(return_value=[1])
    monkeypatch.setattr(pred, "model", m)
    label, conf, src = pred.predict_one(_base_row())
    assert label == "normal" and src == "healthy"
