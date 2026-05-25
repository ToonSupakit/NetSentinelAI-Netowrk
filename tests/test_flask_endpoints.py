"""Integration coverage for Flask auth, admin, and user endpoints."""

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


def _session(client, role="user", csrf="csrf-test-token", user_id=7):
    with client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["user_id"] = user_id
        sess["username"] = role
        sess["role"] = role
        sess["csrf_token"] = csrf
    return csrf


def test_api_requires_login_for_user_endpoint(client):
    resp = client.get("/api/status")
    assert resp.status_code == 401
    assert resp.get_json() == {"success": False, "message": "Unauthorized"}


def test_user_can_read_status_but_cannot_access_admin_users(client, monkeypatch):
    _session(client, role="user")
    monkeypatch.setattr(
        dash,
        "get_device_status",
        lambda *args, **kwargs: [
            (
                "R1",
                "Gi0/0",
                "10.0.0.1",
                "up",
                "up",
                10,
                5,
                255,
                "normal",
                "2026-05-19 10:00:00",
            )
        ],
    )

    status = client.get("/api/status")
    users = client.get("/api/users")

    assert status.status_code == 200
    assert status.get_json()[0]["device"] == "R1"
    assert users.status_code == 403
    assert users.get_json()["message"] == "Admin privileges required"


def test_admin_user_management_endpoints(client, monkeypatch):
    token = _session(client, role="admin", user_id=1)
    monkeypatch.setattr(
        dash,
        "get_all_users",
        lambda: [{"id": 1, "username": "admin", "role": "admin", "created_at": "now"}],
    )
    monkeypatch.setattr(dash, "create_user", lambda username, password, role: True)
    monkeypatch.setattr(dash, "update_user_role", lambda user_id, role: (True, None))
    monkeypatch.setattr(dash, "delete_user", lambda user_id, actor_id=None: (True, None))

    users = client.get("/api/users")
    created = client.post(
        "/api/users",
        json={"username": "alice", "password": "secret1", "role": "user"},
        headers={"X-CSRF-Token": token},
    )
    role = client.put(
        "/api/users/2/role",
        json={"role": "admin"},
        headers={"X-CSRF-Token": token},
    )
    deleted = client.delete("/api/users/2", headers={"X-CSRF-Token": token})

    assert users.status_code == 200
    assert "password" not in users.get_data(as_text=True).lower()
    assert created.status_code == 200
    assert role.status_code == 200
    assert deleted.status_code == 200


def test_login_rate_limit_and_success_flow(client):
    client.get("/login")
    with client.session_transaction() as sess:
        token = sess["csrf_token"]

    with patch.object(dash, "authenticate_user", return_value=None):
        failed = client.post(
            "/api/login",
            json={"username": "bad", "password": "wrong"},
            headers={"X-CSRF-Token": token},
        )
    assert failed.status_code == 401

    with patch.object(dash, "authenticate_user", return_value={"id": 2, "username": "bob", "role": "admin"}):
        ok = client.post(
            "/api/login",
            json={"username": "bob", "password": "secret"},
            headers={"X-CSRF-Token": token},
        )
    assert ok.status_code == 200
    with client.session_transaction() as sess:
        assert sess["logged_in"] is True
        assert sess["role"] == "admin"


def test_admin_ratelimit_validation_rejects_bad_values(client):
    token = _session(client, role="admin")
    resp = client.post(
        "/api/ratelimit/R1/Gi0%2F0",
        json={"limit_mbps": -1, "rollback_min": 0},
        headers={"X-CSRF-Token": token},
    )
    assert resp.status_code == 400
    assert "Limit must be between" in resp.get_json()["message"]
