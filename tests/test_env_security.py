"""Environment settings should save safely without leaking secrets."""

import json

import pytest

import web.dashboard as dash


@pytest.fixture()
def client():
    dash.app.config.update(TESTING=True, SECRET_KEY="test-secret")
    dash.admin_action_attempts.clear()
    with dash.app.test_client() as c:
        with c.session_transaction() as sess:
            sess["logged_in"] = True
            sess["user_id"] = 1
            sess["username"] = "admin"
            sess["role"] = "admin"
            sess["csrf_token"] = "csrf-test-token"
        yield c


def test_get_env_masks_secret_values(client, monkeypatch):
    monkeypatch.setenv("DEVICE_PASSWORD", "device-secret-password")
    monkeypatch.setenv("DEVICE_SECRET", "enable-secret")
    monkeypatch.setenv("SNMP_COMMUNITY", "private-community")
    monkeypatch.setenv("FLASK_SECRET", "a-very-long-dashboard-secret-value")
    monkeypatch.setenv("DEVICE_USERNAME", "netadmin")

    resp = client.get("/api/settings/env")
    body = json.dumps(resp.get_json())

    assert resp.status_code == 200
    assert "device-secret-password" not in body
    assert "enable-secret" not in body
    assert "private-community" not in body
    assert "a-very-long-dashboard-secret-value" not in body
    assert resp.get_json()["data"]["FLASK_SECRET_CONFIGURED"] is True
    assert resp.get_json()["data"]["DEVICE_USERNAME"] == "netadmin"


def test_update_env_file_keeps_unmentioned_secret(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text(
        "DEVICE_PASSWORD=old-password\n" "DEVICE_USERNAME=old-admin\n",
        encoding="utf-8",
    )

    dash.update_env_file(str(env_path), {"DEVICE_USERNAME": "netadmin"})

    text = env_path.read_text(encoding="utf-8")
    assert "DEVICE_PASSWORD=old-password" in text
    assert "DEVICE_USERNAME=netadmin" in text


def test_save_env_rejects_newlines_before_writing(client, tmp_path, monkeypatch):
    env_path = tmp_path / ".env"
    env_path.write_text("SNMP_COMMUNITY=old\n", encoding="utf-8")
    monkeypatch.setattr(dash, "ENV_PATH", str(env_path))

    resp = client.post(
        "/api/settings/env",
        json={"SNMP_COMMUNITY": "line1\nline2"},
        headers={"X-CSRF-Token": "csrf-test-token"},
    )

    assert resp.status_code == 400
    assert "cannot contain newlines" in resp.get_json()["message"]
    assert env_path.read_text(encoding="utf-8") == "SNMP_COMMUNITY=old\n"
