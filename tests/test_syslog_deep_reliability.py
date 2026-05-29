"""Deep Integration, High-Concurrency, and Edge-Case Reliability Tests for Syslog AI Network Server."""

import socket
import threading
import time
import pytest
from unittest.mock import MagicMock, patch
from sqlalchemy import text
from app.syslog_server import SyslogUDPHandler, analyze_syslog_ai, SEVERITIES
from app.db import engine


# -----------------------------------------------------------------------------
# 1. Broad Mnemonic & Vendor Format Parsing Tests
# -----------------------------------------------------------------------------

def test_deep_ai_heuristics_cisco_and_custom():
    """Verify that multiple Cisco and custom mnemonic lines map to precise Thai analysis."""
    # Test physical link state change
    cause, rec = analyze_syslog_ai("LINK", "CHANGED", "Interface FastEthernet0/1, changed state to administratively down")
    assert "อินเทอร์เฟซทางกายภาพ" in cause
    assert "no shutdown" in rec

    # Test line protocol state change
    cause, rec = analyze_syslog_ai("LINEPROTO", "UPDOWN", "Line protocol on Interface Serial0/0/0, changed state to down")
    assert "โปรโตคอลการทำงานบนสายสัญญาณ" in cause
    assert "encapsulation" in rec

    # Test OSPF Adjacency Change
    cause, rec = analyze_syslog_ai("OSPF", "ADJCHG", "Process 10, Nbr 192.168.12.1 on GigabitEthernet0/2 from LOADING to FULL")
    assert "ความสัมพันธ์เพื่อนบ้านของโปรโตคอล" in cause
    assert "OSPF" in cause
    assert "Hello/Dead Timer" in rec

    # Test Config change
    cause, rec = analyze_syslog_ai("SYS", "CONFIG_I", "Configured from console by vty0 (10.0.0.5)")
    assert "มีการแก้ไขหรือเปลี่ยนแปลงรายละเอียดการตั้งค่า" in cause
    assert "Backup" in rec

    # Test IP Duplication
    cause, rec = analyze_syslog_ai("IP", "DUPADDR", "Duplicate address 10.10.10.1 on FastEthernet1/0, sourced by mac 0011.2233.4455")
    assert "ตรวจพบหมายเลขไอพีแอดเดรสชนกัน" in cause
    assert "MAC Address" in rec

    # Test Security ACL access log denied
    cause, rec = analyze_syslog_ai("SEC", "IPACCESSLOGP", "list 110 denied tcp 10.0.0.2(1234) -> 10.1.1.1(80)")
    assert "ตรวจพบแพ็กเก็ตข้อมูลที่โดนสกัดกั้น" in cause
    assert "ACL" in rec or "Access Control List" in rec


# -----------------------------------------------------------------------------
# 2. General Fallback and Robust Phrase Searching
# -----------------------------------------------------------------------------

def test_deep_ai_phrase_fallbacks():
    """Verify general fallback heuristics for raw logs containing vital keywords."""
    # Shutdown phrase
    cause, rec = analyze_syslog_ai("UNKNOWN", "UNKNOWN", "The port GigabitEthernet1/1 was administratively down by network op")
    assert "อินเทอร์เฟซพอร์ตเครือข่ายถูกสั่งปิดการทำงาน" in cause
    assert "no shutdown" in rec

    # Collision phrase
    cause, rec = analyze_syslog_ai("PORT", "ERR", "Late collision detected on segment 1")
    assert "เกิดการชนกันของสัญญาณข้อมูล" in cause
    assert "Speed/Duplex" in rec

    # Conflict/Duplicate phrase
    cause, rec = analyze_syslog_ai("DHCP", "CONFLICT", "IP address conflict duplicate detected for 10.0.0.100")
    assert "ตรวจพบหมายเลขไอพีแอดเดรสชนกัน" in cause
    assert "MAC Address" in rec


# -----------------------------------------------------------------------------
# 3. Malformed and Edge-Case Syslog Packet Parsing
# -----------------------------------------------------------------------------

@pytest.mark.parametrize("raw_msg,expected_facility,expected_mnemonic,expected_severity", [
    # Missing priority header (defaults to Facility User, Severity Notice)
    ("Simple status message here without brackets", "SYS", "GENERIC", "Notice"),
    
    # Priority extreme value: PRI 0 (Emergency)
    ("<0>%LINK-3-CHANGED: Interface Gi0/0 changed state to up", "LINK", "CHANGED", "Emergency"),
    
    # Priority extreme value: PRI 191 (Debug)
    ("<191>%OSPF-7-ADJCHG: Process 1 from FULL to DOWN", "OSPF", "ADJCHG", "Debug"),
    
    # Non-standard priority (e.g. PRI 99 -> 99 // 8 = 12 (Facility), 99 % 8 = 3 (Error))
    ("<99>%SYS-3-CPU_WARNING: CPU usage is high", "SYS", "CPU_WARNING", "Error"),
    
    # Empty message / Malformed content
    ("<13>", "SYS", "GENERIC", "Notice"),
])
def test_syslog_udp_handler_parsing_robustness(raw_msg, expected_facility, expected_mnemonic, expected_severity, monkeypatch):
    """Ensure raw log packets with varying formats parse correctly without exceptions."""
    handler = SyslogUDPHandler()
    
    # Mock SQL interactions
    mock_conn = MagicMock()
    mock_engine = MagicMock()
    mock_engine.connect.return_value.__enter__.return_value = mock_conn
    monkeypatch.setattr("app.syslog_server.engine", mock_engine)
    
    mock_result = MagicMock()
    mock_result.fetchone.return_value = None
    mock_conn.execute.return_value = mock_result

    # Broadcast mocks
    broadcasts = []
    with patch("web.dashboard.socketio.emit", side_effect=lambda ch, data: broadcasts.append((ch, data))):
        handler._parse_and_save(raw_msg, "192.168.1.100")
        
        # Verify db insert call happened
        insert_calls = [c for c in mock_conn.execute.call_args_list if "INSERT INTO device_syslogs" in str(c[0][0])]
        assert len(insert_calls) == 1
        
        # Check values
        params = insert_calls[0][0][1]
        assert params["fac"] == expected_facility
        assert params["mnem"] == expected_mnemonic
        assert params["sev"] == expected_severity
        
        # Check Socket.IO emit
        assert len(broadcasts) == 1
        assert broadcasts[0][0] == "syslog_received"
        assert broadcasts[0][1]["facility"] == expected_facility
        assert broadcasts[0][1]["mnemonic"] == expected_mnemonic
        assert broadcasts[0][1]["severity"] == expected_severity


# -----------------------------------------------------------------------------
# 4. Multi-Threaded Concurrent Logging Stress Test
# -----------------------------------------------------------------------------

def test_syslog_udp_handler_concurrency_stress(monkeypatch):
    """Stress-test Syslog server with high concurrent messages to verify thread safety."""
    handler = SyslogUDPHandler(host="127.0.0.1", port=65505)
    
    # Track details saved to database
    db_inserts = []
    lock = threading.Lock()
    
    def mock_execute(stmt, params=None):
        sql = str(stmt)
        if "INSERT INTO device_syslogs" in sql:
            with lock:
                db_inserts.append(params)
        return MagicMock()

    mock_conn = MagicMock()
    mock_conn.execute = mock_execute
    mock_engine = MagicMock()
    mock_engine.connect.return_value.__enter__.return_value = mock_conn
    monkeypatch.setattr("app.syslog_server.engine", mock_engine)

    # Disable Socket.IO for stress test
    with patch("web.dashboard.socketio.emit") as mock_emit:
        # Send 50 syslog messages simultaneously across 5 concurrent threads
        messages = [
            f"<189>seq_{i}: *May 29 22:00:00: %LINK-5-CHANGED: Port Fa0/{i} state changed"
            for i in range(50)
        ]
        
        def sender_thread(subset):
            for msg in subset:
                handler._parse_and_save(msg, f"10.0.0.{messages.index(msg)}")

        threads = []
        chunk_size = 10
        for i in range(0, 50, chunk_size):
            chunk = messages[i:i + chunk_size]
            t = threading.Thread(target=sender_thread, args=(chunk,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # Check all 50 insertions completed safely
        assert len(db_inserts) == 50
        assert handler.received_count == 50
        
        # Verify the sequential integrity of stored records
        for i, record in enumerate(db_inserts):
            assert record["fac"] == "LINK"
            assert record["sev"] == "Notice"
            assert record["mnem"] == "CHANGED"
            assert "state changed" in record["msg"]


# -----------------------------------------------------------------------------
# 5. Socket.IO Broadcast Stability Under Intermittent Drops
# -----------------------------------------------------------------------------

def test_syslog_socketio_failure_resilience(monkeypatch):
    """Ensure that Syslog server remains completely stable even if Socket.IO crashes or drops."""
    handler = SyslogUDPHandler()
    
    # DB mock
    mock_conn = MagicMock()
    mock_engine = MagicMock()
    mock_engine.connect.return_value.__enter__.return_value = mock_conn
    monkeypatch.setattr("app.syslog_server.engine", mock_engine)

    # Simulate Socket.IO throwing standard connection or runtime exceptions
    with patch("web.dashboard.socketio.emit", side_effect=RuntimeError("Socket.IO client disconnected!")):
        # The syslog handler must catch the error internally and continue running perfectly
        try:
            handler._parse_and_save("<189>%SYS-5-CONFIG_I: Saved to startup-config", "10.10.1.1")
        except Exception as e:
            pytest.fail(f"Syslog server crashed on Socket.IO failure: {e}")
        
        # Verify the database entry was still committed
        assert mock_conn.commit.called
