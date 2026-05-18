"""Unit tests for collector parsing and labeling (no live devices)."""
from app.collector import get_label, parse_interfaces, should_skip


def test_parse_interfaces_minimal():
    raw = """
GigabitEthernet0/0 is up, line protocol is up
  reliability 255/255, txload 10/255, rxload 5/255
     0 input errors
"""
    out = parse_interfaces(raw)
    assert "GigabitEthernet0/0" in out
    assert out["GigabitEthernet0/0"]["phys"] == "up"
    assert out["GigabitEthernet0/0"]["proto"] == "up"
    assert out["GigabitEthernet0/0"]["reliability"] == "255"
    assert out["GigabitEthernet0/0"]["txload"] == "10"
    assert out["GigabitEthernet0/0"]["rxload"] == "5"
    assert out["GigabitEthernet0/0"]["input_errors"] == "0"


def test_should_skip_unassigned():
    assert should_skip("Gi0/0", "unassigned", False) is True


def test_get_label_physical_down():
    assert get_label(0, 0, 1, 1, 255, 0, False) == "anomaly"


def test_get_label_normal():
    assert get_label(1, 1, 1, 1, 255, 0, False) == "normal"


def test_get_label_high_load(monkeypatch):
    import app.collector as c

    monkeypatch.setattr(c, "THRESHOLD_LOAD", 5)
    assert get_label(1, 1, 200, 1, 255, 0, False) == "anomaly"
