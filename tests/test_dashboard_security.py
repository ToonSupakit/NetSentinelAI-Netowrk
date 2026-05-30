"""Dashboard security and settings hardening tests."""

from unittest.mock import patch

import pytest

import web.dashboard as dash


@pytest.fixture()
def client():
    dash.app.config.update(TESTING=True, SECRET_KEY="test-secret")
    dash.admin_action_attempts.clear()
    dash.login_attempts.clear()
    with dash.app.test_client() as c:
        yield c


def _admin_session(client, csrf="csrf-test-token", user_id=1):
    with client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["user_id"] = user_id
        sess["username"] = "admin"
        sess["role"] = "admin"
        sess["csrf_token"] = csrf
    return csrf


def test_mutating_api_requires_csrf(client):
    _admin_session(client)
    resp = client.post("/api/fix/R1/Gi0%2F1")
    assert resp.status_code == 400
    assert resp.get_json()["message"] == "Invalid CSRF token"


def test_admin_fix_accepts_valid_csrf(client):
    token = _admin_session(client)
    with patch.object(dash.socketio, "start_background_task", lambda *a, **k: None):
        resp = client.post("/api/fix/R1/Gi0%2F1", headers={"X-CSRF-Token": token})
    assert resp.status_code == 200
    assert resp.get_json()["queued"] is True


def test_admin_action_rate_limit(client, monkeypatch):
    token = _admin_session(client)
    monkeypatch.setattr(dash, "_ADMIN_ACTION_LIMIT", 1)
    with patch.object(dash.socketio, "start_background_task", lambda *a, **k: None):
        first = client.post("/api/fix/R1/Gi0%2F1", headers={"X-CSRF-Token": token})
        second = client.post("/api/fix/R1/Gi0%2F1", headers={"X-CSRF-Token": token})
    assert first.status_code == 200
    assert second.status_code == 429


def test_login_uses_csrf_and_sets_user_session(client):
    client.get("/login")
    with client.session_transaction() as sess:
        token = sess["csrf_token"]
    with patch.object(dash, "authenticate_user", return_value={"id": 7, "username": "alice", "role": "user"}):
        resp = client.post(
            "/api/login",
            json={"username": "alice", "password": "secret"},
            headers={"X-CSRF-Token": token},
        )
    assert resp.status_code == 200
    with client.session_transaction() as sess:
        assert sess["user_id"] == 7
        assert sess["role"] == "user"


def test_settings_config_validation_rejects_bad_interval(client):
    token = _admin_session(client)
    payload = {
        "collector": {"interval": 0},
        "model": {
            "path": "models/anomaly_model_v2.pkl",
            "threshold_load": 20,
            "threshold_reliability": 200,
            "threshold_errors": 10,
        },
        "anomaly": {"skip_types": []},
        "data_retention": {"enabled": True, "days": 30},
    }
    resp = client.post(
        "/api/settings/config",
        json=payload,
        headers={"X-CSRF-Token": token},
    )
    assert resp.status_code == 400
    assert "collector.interval" in resp.get_json()["message"]


def test_settings_devices_validation_rejects_duplicate_names(client):
    token = _admin_session(client)
    payload = {
        "devices": [
            {"name": "R1", "host": "10.0.0.1", "device_type": "cisco_ios"},
            {"name": "R1", "host": "10.0.0.2", "device_type": "cisco_ios"},
        ]
    }
    resp = client.post(
        "/api/settings/devices",
        json=payload,
        headers={"X-CSRF-Token": token},
    )
    assert resp.status_code == 400
    assert "Duplicate device name" in resp.get_json()["message"]


def test_env_update_preserves_comments_order_and_skips_blank_secrets(client, tmp_path, monkeypatch):
    token = _admin_session(client)
    env_path = tmp_path / ".env"
    env_path.write_text(
        "# keep this comment\n" "DEVICE_USERNAME=oldadmin\n" "DEVICE_PASSWORD=oldpass\n" "UNRELATED=value\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(dash, "ENV_PATH", str(env_path))

    resp = client.post(
        "/api/settings/env",
        json={"DEVICE_USERNAME": "netadmin", "DEVICE_PASSWORD": ""},
        headers={"X-CSRF-Token": token},
    )

    assert resp.status_code == 200
    text = env_path.read_text(encoding="utf-8")
    assert "# keep this comment" in text
    assert "DEVICE_USERNAME=netadmin" in text
    assert "DEVICE_PASSWORD=oldpass" in text
    assert "UNRELATED=value" in text


def test_env_validation_rejects_unsupported_key(client):
    token = _admin_session(client)
    resp = client.post(
        "/api/settings/env",
        json={"DB_URL": "mysql://example"},
        headers={"X-CSRF-Token": token},
    )
    assert resp.status_code == 400
    assert "Unsupported environment key" in resp.get_json()["message"]
