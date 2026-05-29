"""Unit and integration tests for Syslog AI Analyzer & Web Terminal Console."""

import socket
from datetime import datetime
from unittest.mock import MagicMock, patch
import pytest
from sqlalchemy import text

# Import the application components to test
from app.syslog_server import (
    analyze_syslog_ai,
    analyze_cause_on_the_fly,
    SyslogUDPHandler,
    SEVERITIES,
)
import web.dashboard as dash


# ---------------------------------------------------------
# Fixtures
# ---------------------------------------------------------

@pytest.fixture()
def client():
    """Flask test client fixture."""
    dash.app.config.update(TESTING=True, SECRET_KEY="test-secret")
    dash.admin_action_attempts.clear()
    dash.login_attempts.clear()
    with dash.app.test_client() as c:
        yield c


def _session(client, role="user", csrf="csrf-test-token", user_id=7):
    """Helper to mock user session logins."""
    with client.session_transaction() as sess:
        sess["logged_in"] = True
        sess["user_id"] = user_id
        sess["username"] = role
        sess["role"] = role
        sess["csrf_token"] = csrf
    return csrf


# ---------------------------------------------------------
# 1. Feature A: Syslog AI Heuristics Tests
# ---------------------------------------------------------

def test_analyze_syslog_ai_known_mnemonics():
    """Verify that specific Cisco mnemonics yield correct Thai descriptions and guidelines."""
    # LINK CHANGED
    cause, suggestion = analyze_syslog_ai("LINK", "CHANGED", "Interface GigabitEthernet0/1, changed state to down")
    assert "อินเทอร์เฟซทางกายภาพมีการเปลี่ยนแปลงสถานะ" in cause
    assert "no shutdown" in suggestion

    # LINEPROTO UPDOWN
    cause, suggestion = analyze_syslog_ai("LINEPROTO", "UPDOWN", "Line protocol on Interface GigabitEthernet0/1, changed state to down")
    assert "โปรโตคอลการทำงานบนสายสัญญาณเปลี่ยนสถานะ" in cause
    assert "encapsulation" in suggestion

    # OSPF ADJCHG
    cause, suggestion = analyze_syslog_ai("OSPF", "ADJCHG", "Process 1, Nbr 10.0.0.2 on GigabitEthernet0/1 from FULL to DOWN")
    assert "ความสัมพันธ์เพื่อนบ้านของโปรโตคอลการจัดเส้นทาง OSPF" in cause
    assert "Hello/Dead Timer" in suggestion

    # SYS CONFIG_I
    cause, suggestion = analyze_syslog_ai("SYS", "CONFIG_I", "Configured from console by admin on vty0")
    assert "มีการแก้ไขหรือเปลี่ยนแปลงรายละเอียดการตั้งค่า" in cause
    assert "Run Backup" in suggestion

    # SEC IPACCESSLOGP
    cause, suggestion = analyze_syslog_ai("SEC", "IPACCESSLOGP", "list 101 denied tcp 10.0.0.5")
    assert "ตรวจพบแพ็กเก็ตข้อมูลที่โดนสกัดกั้นหรือตรวจสอบ" in cause
    assert "Access Control List" in suggestion or "ACL" in suggestion

    # IP DUPADDR
    cause, suggestion = analyze_syslog_ai("IP", "DUPADDR", "Duplicate address 10.0.0.1 on GigabitEthernet0/1")
    assert "ตรวจพบหมายเลขไอพีแอดเดรสชนกัน" in cause
    assert "MAC Address" in suggestion


def test_analyze_syslog_ai_fallback_keywords():
    """Verify general fallback heuristics matching specific error phrases."""
    # Duplicate IP keyword fallback
    cause, suggestion = analyze_syslog_ai("OTHER", "OTHER", "IP address conflict duplicate detected for 192.168.1.100")
    assert "ตรวจพบหมายเลขไอพีแอดเดรสชนกัน" in cause

    # Shutdown keyword fallback
    cause, suggestion = analyze_syslog_ai("OTHER", "OTHER", "Interface Port1 is administratively down")
    assert "อินเทอร์เฟซพอร์ตเครือข่ายถูกสั่งปิดการทำงานแบบจงใจ" in cause
    assert "no shutdown" in suggestion

    # Collision keyword fallback
    cause, suggestion = analyze_syslog_ai("OTHER", "OTHER", "Late collision detected on port 2")
    assert "เกิดการชนกันของสัญญาณข้อมูลบนสายส่ง" in cause
    assert "Speed/Duplex" in suggestion


def test_analyze_syslog_ai_generic_default():
    """Verify default standard instructions when no mnemonic or keyword matches."""
    cause, suggestion = analyze_syslog_ai("CUSTOM_FAC", "UNKNOWN_MNEM", "Some minor message details here")
    assert "เกิดเหตุการณ์ประเภท CUSTOM_FAC" in cause
    assert "UNKNOWN_MNEM" in cause
    assert "AI Sandbox" in suggestion


def test_analyze_cause_on_the_fly_exception_safety():
    """Ensure analyze_cause_on_the_fly is fully exception-safe and returns defaults."""
    with patch("app.syslog_server.analyze_syslog_ai", side_effect=ValueError("Test crash")):
        cause, suggestion = analyze_cause_on_the_fly("SYS", "GENERIC", "Something")
        assert "ไม่สามารถระบุสาเหตุทางปัญญาประดิษฐ์ย้อนหลังได้สำเร็จ" in cause
        assert "เชื่อมโยงข้อมูล CLI เพิ่มเติม" in suggestion


# ---------------------------------------------------------
# 2. Feature A: Syslog Server UDP Receiver & DB Tests
# ---------------------------------------------------------

def test_syslog_udp_handler_start_stop():
    """Verify that SyslogUDPHandler socket bindings operate and failover correctly."""
    handler = SyslogUDPHandler(host="127.0.0.1", port=65500)
    
    mock_socket = MagicMock()
    with patch("socket.socket", return_value=mock_socket):
        # Successful Bind on primary port
        handler.start()
        assert handler.running is True
        mock_socket.bind.assert_called_with(("127.0.0.1", 65500))
        handler.stop()
        assert handler.running is False
        mock_socket.close.assert_called_once()

    # Permission denied failover simulation
    handler_failover = SyslogUDPHandler(host="127.0.0.1", port=514)
    mock_socket_fail = MagicMock()
    mock_socket_fail.bind.side_effect = PermissionError("Permission denied for privileged port 514")
    
    mock_socket_alt = MagicMock()
    
    # We mock successive socket.socket calls: first returns failed socket, second returns failover socket
    with patch("socket.socket", side_effect=[mock_socket_fail, mock_socket_alt]):
        handler_failover.start()
        # Verify fallback was triggered
        assert handler_failover.port == 5140
        assert handler_failover.running is True
        mock_socket_alt.bind.assert_called_with(("127.0.0.1", 5140))
        handler_failover.stop()


def test_syslog_udp_handler_parse_and_save(monkeypatch):
    """Verify raw RFC 3164 cisco syslog packet parsing and database persistence."""
    handler = SyslogUDPHandler()
    
    # Mock database connections
    mock_conn = MagicMock()
    mock_engine = MagicMock()
    mock_engine.connect.return_value.__enter__.return_value = mock_conn
    monkeypatch.setattr("app.syslog_server.engine", mock_engine)
    
    # Mock GNS3 device database query to return "SW-L2-1" for remote sender IP "10.0.0.9"
    mock_result_device = MagicMock()
    mock_result_device.fetchone.return_value = ("SW-L2-1",)
    
    # Mock execute to return specific query results
    executed_statements = []
    def mock_execute(stmt, params=None):
        sql = str(stmt)
        executed_statements.append((sql, params))
        if "SELECT name FROM devices" in sql:
            return mock_result_device
        return MagicMock()
        
    mock_conn.execute = mock_execute

    # Mock Socket.IO broadcast to verify it triggers
    broadcast_data = []
    with patch("web.dashboard.socketio.emit", side_effect=lambda ch, data: broadcast_data.append((ch, data))):
        # Raw syslog cisco log message
        raw_packet = "<189>82: *May 24 16:45:29.812: %LINK-5-CHANGED: Interface GigabitEthernet0/0, changed state to down"
        handler._parse_and_save(raw_packet, "10.0.0.9")
        
        # Verify device lookup query occurred
        assert any("SELECT name FROM devices" in item[0] for item in executed_statements)
        
        # Verify insertion SQL executed with parsed items
        insert_sql = None
        insert_params = None
        for sql, params in executed_statements:
            if "INSERT INTO device_syslogs" in sql:
                insert_sql = sql
                insert_params = params
                break
                
        assert insert_sql is not None
        assert insert_params["dev"] == "SW-L2-1"
        assert insert_params["ip"] == "10.0.0.9"
        assert insert_params["fac"] == "LINK"
        assert insert_params["sev"] == "Notice"  # PRI 189 -> severity code 189 % 8 = 5 (Notice)
        assert insert_params["mnem"] == "CHANGED"
        assert "Interface GigabitEthernet0/0, changed state to down" in insert_params["msg"]
        assert "อินเทอร์เฟซทางกายภาพมีการเปลี่ยนแปลงสถานะ" in insert_params["cause"]
        
        # Verify real-time socket.io broadcast was triggered
        assert len(broadcast_data) == 1
        channel, socket_payload = broadcast_data[0]
        assert channel == "syslog_received"
        assert socket_payload["device_name"] == "SW-L2-1"
        assert socket_payload["ip_address"] == "10.0.0.9"
        assert socket_payload["facility"] == "LINK"
        assert socket_payload["mnemonic"] == "CHANGED"
        assert socket_payload["severity"] == "Notice"


# ---------------------------------------------------------
# 3. Feature A: Flask REST API /logs Integration Tests
# ---------------------------------------------------------

def test_logs_page_requires_login(client):
    """Verify security guard: /logs page requires active session login."""
    resp = client.get("/logs")
    assert resp.status_code == 302  # Redirects to login
    assert "/login" in resp.headers["Location"]


def test_logs_page_loads_for_logged_in_user(client):
    """Verify /logs page loads successfully for authenticated user."""
    _session(client, role="user")
    resp = client.get("/logs")
    assert resp.status_code == 200
    assert "System Logs" in resp.get_data(as_text=True) or "logs" in resp.get_data(as_text=True)


def test_api_get_syslogs_requires_login(client):
    """Verify security guard: /api/syslogs API requires active session login."""
    resp = client.get("/api/syslogs")
    assert resp.status_code == 401


def test_api_get_syslogs_filtered(client, monkeypatch):
    """Verify /api/syslogs retrieves and filters logged database syslogs."""
    _session(client, role="user")
    
    mock_conn = MagicMock()
    mock_engine = MagicMock()
    mock_engine.connect.return_value.__enter__.return_value = mock_conn
    monkeypatch.setattr(dash, "engine", mock_engine)
    
    # Mock SQL execution return rows
    mock_rows = [
        ("SW-L2-1", "10.0.0.9", "LINK", "Notice", "CHANGED", "GigabitEthernet0/0 down", "RCA details", "Fix details", datetime(2026, 5, 24, 16, 45, 0))
    ]
    mock_conn.execute.return_value.fetchall.return_value = mock_rows
    
    # Call with full filters
    resp = client.get("/api/syslogs?device=SW-L2-1&severity=Notice&search=Gigabit")
    
    assert resp.status_code == 200
    json_data = resp.get_json()
    assert json_data["success"] is True
    assert len(json_data["logs"]) == 1
    assert json_data["logs"][0]["device_name"] == "SW-L2-1"
    assert json_data["logs"][0]["ip_address"] == "10.0.0.9"
    assert json_data["logs"][0]["facility"] == "LINK"
    assert json_data["logs"][0]["severity"] == "Notice"
    assert json_data["logs"][0]["mnemonic"] == "CHANGED"
    assert json_data["logs"][0]["message"] == "GigabitEthernet0/0 down"
    assert json_data["logs"][0]["ai_cause"] == "RCA details"
    assert json_data["logs"][0]["ai_suggestion"] == "Fix details"
    assert json_data["logs"][0]["received_at"] == "2026-05-24 16:45:00"


def test_api_analyze_syslog_ondemand_sandbox(client):
    """Verify on-demand NLP/AI sandbox analyzer parses raw pasted CLI strings."""
    csrf_token = _session(client, role="user")
    
    # Test blank payload validation (needs CSRF since it is a mutating POST request)
    resp_empty = client.post("/api/syslogs/analyze", json={}, headers={"X-CSRF-Token": csrf_token})
    assert resp_empty.status_code == 400
    assert resp_empty.get_json()["message"] == "Log text required"

    # Test valid cisco syslog text string
    syslog_text = "May 24 16:45:29: %OSPF-5-ADJCHG: Process 10, Nbr 10.0.0.2 on Gi0/1 from LOADING to FULL, OSPF_ADJ_OK"
    resp = client.post("/api/syslogs/analyze", json={"log_text": syslog_text}, headers={"X-CSRF-Token": csrf_token})
    
    assert resp.status_code == 200
    json_data = resp.get_json()
    assert json_data["success"] is True
    assert json_data["facility"] == "OSPF"
    assert json_data["mnemonic"] == "ADJCHG"
    assert "Process 10, Nbr 10.0.0.2" in json_data["message"]
    assert "ความสัมพันธ์เพื่อนบ้านของโปรโตคอลการจัดเส้นทาง OSPF" in json_data["ai_cause"]
    assert "Hello/Dead Timer" in json_data["ai_suggestion"]


# ---------------------------------------------------------
# 4. Syslog Server Status & Test Endpoints
# ---------------------------------------------------------

def test_syslog_handler_get_status():
    """Verify get_status returns correct runtime status dict."""
    handler = SyslogUDPHandler(host="127.0.0.1", port=65501)
    status = handler.get_status()
    assert status["running"] is False
    assert status["port"] == 65501
    assert status["received_count"] == 0
    assert status["started_at"] is None
    assert status["bind_error"] is None


def test_syslog_handler_send_test(monkeypatch):
    """Verify send_test sends a UDP packet to the configured port."""
    handler = SyslogUDPHandler(host="127.0.0.1", port=65502)
    handler.running = True

    mock_sock = MagicMock()
    with patch("socket.socket", return_value=mock_sock):
        ok, msg = handler.send_test()
        assert ok is True
        assert "65502" in msg
        mock_sock.sendto.assert_called_once()
        mock_sock.close.assert_called_once()


def test_api_syslog_status_requires_login(client):
    """Verify /api/syslog/status requires authentication."""
    resp = client.get("/api/syslog/status")
    assert resp.status_code == 401


def test_api_syslog_status_returns_info(client, monkeypatch):
    """Verify /api/syslog/status returns server info."""
    _session(client, role="user")

    mock_instance = MagicMock()
    mock_instance.get_status.return_value = {
        "running": True,
        "port": 5140,
        "host": "0.0.0.0",
        "received_count": 42,
        "started_at": "2026-05-29 10:00:00",
        "bind_error": None,
    }
    monkeypatch.setattr("app.syslog_server.syslog_server_instance", mock_instance)

    resp = client.get("/api/syslog/status")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert data["running"] is True
    assert data["port"] == 5140
    assert data["received_count"] == 42


def test_api_syslog_test_requires_login(client):
    """Verify /api/syslog/test requires authentication (or CSRF)."""
    resp = client.post("/api/syslog/test")
    assert resp.status_code in (400, 401)  # CSRF middleware may fire before login check


def test_api_syslog_test_sends_message(client, monkeypatch):
    """Verify /api/syslog/test triggers a test syslog message."""
    csrf = _session(client, role="user")

    mock_instance = MagicMock()
    mock_instance.running = True
    mock_instance.send_test.return_value = (True, "Test syslog sent to 127.0.0.1:5140")
    monkeypatch.setattr("app.syslog_server.syslog_server_instance", mock_instance)

    resp = client.post("/api/syslog/test", headers={"X-CSRF-Token": csrf})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert "Test syslog sent" in data["message"]


def test_api_syslog_test_server_not_running(client, monkeypatch):
    """Verify /api/syslog/test returns 503 when server is not running."""
    csrf = _session(client, role="user")

    mock_instance = MagicMock()
    mock_instance.running = False
    monkeypatch.setattr("app.syslog_server.syslog_server_instance", mock_instance)

    resp = client.post("/api/syslog/test", headers={"X-CSRF-Token": csrf})
    assert resp.status_code == 503
    data = resp.get_json()
    assert data["success"] is False

