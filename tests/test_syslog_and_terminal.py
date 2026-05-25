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
# 4. Feature B: Web Terminal Routing & SocketIO Tests
# ---------------------------------------------------------

def test_terminal_page_requires_admin(client):
    """Verify that only admins can access `/terminal` page."""
    # No login -> redirect
    resp1 = client.get("/terminal")
    assert resp1.status_code == 302

    # Standard User role -> redirect back to /
    _session(client, role="user")
    resp2 = client.get("/terminal")
    assert resp2.status_code == 302
    assert resp2.headers["Location"] == "/"

    # Admin role -> 200 Success
    _session(client, role="admin")
    resp3 = client.get("/terminal")
    assert resp3.status_code == 200
    assert "Web Console" in resp3.get_data(as_text=True) or "terminal" in resp3.get_data(as_text=True)


def test_socketio_terminal_connect_missing_device(monkeypatch):
    """Assert terminal_connect rejects request if device_name is missing."""
    emitted = []
    def mock_emit(channel, payload, to=None):
        emitted.append((channel, payload, to))
        
    monkeypatch.setattr(dash.socketio, "emit", mock_emit)
    
    # Mock sid using clean monkeypatching to avoid proxy inspection errors
    mock_req = MagicMock()
    mock_req.sid = "sid-123"
    monkeypatch.setattr(dash, "request", mock_req)
    
    dash._terminal_connect({})
        
    assert len(emitted) == 1
    assert emitted[0][0] == "terminal_status"
    assert emitted[0][1]["status"] == "error"
    assert "Device name required" in emitted[0][1]["message"]


def test_socketio_terminal_connect_unregistered_device(monkeypatch):
    """Assert terminal_connect rejects unregistered device name lookup."""
    emitted = []
    def mock_emit(channel, payload, to=None):
        emitted.append((channel, payload, to))
        
    monkeypatch.setattr(dash.socketio, "emit", mock_emit)
    
    # Mock configuration lookup to return None
    monkeypatch.setattr(dash, "get_device_by_name", lambda name: None)
    
    mock_req = MagicMock()
    mock_req.sid = "sid-123"
    monkeypatch.setattr(dash, "request", mock_req)
    
    dash._terminal_connect({"device_name": "NonExistent"})
        
    assert any(
        e[0] == "terminal_status" and e[1]["status"] == "error" and "not registered" in e[1]["message"]
        for e in emitted
    )


def test_socketio_terminal_connect_success(monkeypatch):
    """Verify terminal connection lifecycle, mock netmiko instance, keepalive VTY command stream."""
    emitted = []
    def mock_emit(channel, payload, to=None):
        emitted.append((channel, payload, to))
        
    monkeypatch.setattr(dash.socketio, "emit", mock_emit)
    
    # Mock configuration lookup to return device host and type info
    monkeypatch.setattr(dash, "get_device_by_name", lambda name: {"host": "10.0.0.1", "device_type": "cisco_ios"})
    
    # Mock background thread start task
    tasks_spawned = []
    def mock_start_task(fn, *args, **kwargs):
        tasks_spawned.append((fn, args, kwargs))
        return MagicMock()
    monkeypatch.setattr(dash.socketio, "start_background_task", mock_start_task)
    
    # Mock ConnectHandler
    mock_connect_obj = MagicMock()
    mock_connect_handler = MagicMock(return_value=mock_connect_obj)
    monkeypatch.setattr("web.dashboard.ConnectHandler", mock_connect_handler)
    
    dash.active_terminals.clear()
    
    mock_req = MagicMock()
    mock_req.sid = "sid-123"
    monkeypatch.setattr(dash, "request", mock_req)
    
    dash._terminal_connect({"device_name": "SW-L2-1"})
        
    # Verify Connection handler was invoked
    mock_connect_handler.assert_called_once()
    assert mock_connect_handler.call_args[1]["host"] == "10.0.0.1"
    assert mock_connect_handler.call_args[1]["device_type"] == "cisco_ios"
    mock_connect_obj.enable.assert_called_once()
    
    # Verify active terminal state stored
    assert "sid-123" in dash.active_terminals
    assert dash.active_terminals["sid-123"]["device"] == "SW-L2-1"
    assert dash.active_terminals["sid-123"]["read_thread_running"] is True
    
    # Verify background task spawned
    assert len(tasks_spawned) == 1
    assert tasks_spawned[0][0] == dash.read_vty_stream
    assert tasks_spawned[0][1][0] == "sid-123"
    
    # Verify status feedback sent
    assert any(e[0] == "terminal_status" and e[1]["status"] == "connected" for e in emitted)


def test_socketio_terminal_input(monkeypatch):
    """Verify input character keystroke writing directly to Netmiko's write_channel."""
    mock_conn = MagicMock()
    dash.active_terminals = {
        "sid-123": {
            "net_connect": mock_conn,
            "device": "SW-L2-1",
            "read_thread_running": True
        }
    }
    
    mock_req = MagicMock()
    mock_req.sid = "sid-123"
    monkeypatch.setattr(dash, "request", mock_req)
    
    # Type command sequence in console
    dash._terminal_input({"data": "show ip interface brief\r"})
        
    mock_conn.write_channel.assert_called_once_with("show ip interface brief\r")


def test_socketio_disconnect_garbage_collection(monkeypatch):
    """Verify active terminal connection is immediately garbage collected on websocket disconnect."""
    mock_conn = MagicMock()
    dash.active_terminals = {
        "sid-123": {
            "net_connect": mock_conn,
            "device": "SW-L2-1",
            "read_thread_running": True
        }
    }
    
    # Emits disconnected status
    emitted = []
    def mock_emit(channel, payload, to=None):
        emitted.append((channel, payload, to))
    monkeypatch.setattr(dash.socketio, "emit", mock_emit)
    
    mock_req = MagicMock()
    mock_req.sid = "sid-123"
    monkeypatch.setattr(dash, "request", mock_req)
    
    dash._socketio_disconnect_terminal()
        
    # Session removed from list
    assert "sid-123" not in dash.active_terminals
    mock_conn.disconnect.assert_called_once()
    assert any(e[0] == "terminal_status" and e[1]["status"] == "disconnected" for e in emitted)


def test_read_vty_stream_loop(monkeypatch):
    """Verify VTY background read_channel generator loop emits console output payload."""
    mock_conn = MagicMock()
    mock_conn.read_channel.side_effect = ["Switch#", "", ConnectionError("Disconnected")]
    
    dash.active_terminals = {
        "sid-123": {
            "net_connect": mock_conn,
            "device": "SW-L2-1",
            "read_thread_running": True
        }
    }
    
    emitted = []
    def mock_emit(channel, payload, to=None):
        emitted.append((channel, payload, to))
    monkeypatch.setattr(dash.socketio, "emit", mock_emit)
    monkeypatch.setattr(dash.socketio, "sleep", lambda x: None)
    
    # Run reader function - will break out when ConnectionError raised
    dash.read_vty_stream("sid-123", mock_conn)
    
    # Assert output string emitted
    assert any(e[0] == "terminal_output" and e[1]["data"] == "Switch#" for e in emitted)
    assert "sid-123" not in dash.active_terminals  # Cleaned up


def test_vty_keepalive_loop_sends_non_intrusive_keystroke(monkeypatch):
    """Verify VTY keepalive thread writes whitespace backspaces to active console terminals."""
    mock_conn1 = MagicMock()
    mock_conn2 = MagicMock()
    
    dash.active_terminals = {
        "sid-1": {
            "net_connect": mock_conn1,
            "device": "SW-L2-1",
            "read_thread_running": True
        },
        "sid-2": {
            "net_connect": mock_conn2,
            "device": "SW-L2-2",
            "read_thread_running": True
        }
    }
    
    # Make sleep raise an exception to exit the infinite while True loop immediately after first check
    class LoopDone(Exception):
        pass
        
    def mock_sleep(seconds):
        if seconds == 60:
            # First tick: execute keepalive logic, then terminate loop
            pass
        else:
            raise LoopDone()
            
    sleep_count = 0
    def mock_sleep_ticks(seconds):
        nonlocal sleep_count
        sleep_count += 1
        if sleep_count > 1:
            raise LoopDone()
            
    monkeypatch.setattr(dash.socketio, "sleep", mock_sleep_ticks)
    
    with pytest.raises(LoopDone):
        dash.vty_keepalive_loop()
        
    # Assert both active sessions received keepalive sequence " \b"
    mock_conn1.write_channel.assert_called_once_with(" \b")
    mock_conn2.write_channel.assert_called_once_with(" \b")
