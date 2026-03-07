import pytest
from src.scanner import (
    get_service_name,
    is_risky,
    scan_single_port,
    generate_report
)


# ─────────────────────────────────────────
# TEST: get_service_name
# ─────────────────────────────────────────

def test_known_port_returns_correct_service():
    assert get_service_name(80) == "HTTP"
    assert get_service_name(22) == "SSH"
    assert get_service_name(443) == "HTTPS"
    assert get_service_name(3306) == "MySQL"


def test_unknown_port_returns_unknown():
    assert get_service_name(9999) == "unknown"
    assert get_service_name(0) == "unknown"


# ─────────────────────────────────────────
# TEST: is_risky
# ─────────────────────────────────────────

def test_risky_ports_flagged_correctly():
    assert is_risky(21) == True   # FTP — unencrypted
    assert is_risky(23) == True   # Telnet — very dangerous
    assert is_risky(6379) == True # Redis — often exposed accidentally


def test_safe_ports_not_flagged():
    assert is_risky(443) == False  # HTTPS — safe
    assert is_risky(22) == False   # SSH — encrypted


# ─────────────────────────────────────────
# TEST: generate_report
# ─────────────────────────────────────────

def test_report_structure():
    fake_ports = [
        {"port": 80, "state": "open", "service": "HTTP", "risky": False, "scanned_at": "2024-01-01"}
    ]
    report = generate_report("127.0.0.1", fake_ports)

    assert "target" in report
    assert "scan_time" in report
    assert "total_open_ports" in report
    assert "risk_level" in report
    assert report["total_open_ports"] == 1


def test_report_risk_level_high_when_risky_port():
    risky_ports = [
        {"port": 23, "state": "open", "service": "Telnet", "risky": True, "scanned_at": "2024-01-01"}
    ]
    report = generate_report("127.0.0.1", risky_ports)
    assert report["risk_level"] == "HIGH"


def test_report_risk_level_low_when_no_risky_ports():
    safe_ports = [
        {"port": 443, "state": "open", "service": "HTTPS", "risky": False, "scanned_at": "2024-01-01"}
    ]
    report = generate_report("127.0.0.1", safe_ports)
    assert report["risk_level"] == "LOW"


def test_empty_scan_report():
    report = generate_report("127.0.0.1", [])
    assert report["total_open_ports"] == 0
    assert report["risk_level"] == "LOW"
