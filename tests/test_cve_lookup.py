import pytest
from unittest.mock import patch, MagicMock
from src.cve_lookup import (
    extract_severity,
    extract_description,
    enrich_scan_results,
    get_cves_for_service,
    SERVICE_KEYWORDS
)


# ─────────────────────────────────────────
# TEST: SERVICE_KEYWORDS mapping
# ─────────────────────────────────────────

def test_ssh_has_keyword():
    assert SERVICE_KEYWORDS["SSH"] == "OpenSSH"

def test_unknown_service_has_no_keyword():
    assert SERVICE_KEYWORDS["unknown"] is None


# ─────────────────────────────────────────
# TEST: extract_severity
# ─────────────────────────────────────────

def test_extract_severity_v31():
    """Test that CVSS v3.1 score is parsed correctly"""
    fake_cve = {
        "metrics": {
            "cvssMetricV31": [{
                "cvssData": {
                    "baseScore": 9.8,
                    "baseSeverity": "CRITICAL"
                }
            }]
        }
    }
    score, severity = extract_severity(fake_cve)
    assert score == 9.8
    assert severity == "CRITICAL"


def test_extract_severity_empty_metrics():
    """Test graceful handling when no metrics exist"""
    fake_cve = {"metrics": {}}
    score, severity = extract_severity(fake_cve)
    assert score == 0.0
    assert severity == "UNKNOWN"


# ─────────────────────────────────────────
# TEST: extract_description
# ─────────────────────────────────────────

def test_extract_description_english():
    fake_cve = {
        "descriptions": [
            {"lang": "en", "value": "A critical vulnerability in OpenSSH"},
            {"lang": "es", "value": "Una vulnerabilidad critica"}
        ]
    }
    desc = extract_description(fake_cve)
    assert desc == "A critical vulnerability in OpenSSH"


def test_extract_description_empty():
    fake_cve = {"descriptions": []}
    desc = extract_description(fake_cve)
    assert "No description" in desc


# ─────────────────────────────────────────
# TEST: enrich_scan_results
# We use mock here so we don't actually
# hit the NVD API during tests
# ─────────────────────────────────────────

def test_enrich_adds_cve_fields():
    """
    Test that enrich_scan_results adds
    cves and cve_count fields to each port result.

    We MOCK the API call so tests don't need internet.
    """
    fake_ports = [
        {"port": 22, "service": "SSH", "state": "open", "risky": False}
    ]

    fake_cves = [
        {
            "cve_id": "CVE-2023-38408",
            "severity": "CRITICAL",
            "score": 9.8,
            "description": "Remote code execution in OpenSSH",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-38408"
        }
    ]

    # Mock means: "pretend get_cves_for_service returns fake_cves"
    # so we never actually call the NVD API in tests
    with patch("src.cve_lookup.get_cves_for_service", return_value=fake_cves):
        result = enrich_scan_results(fake_ports)

    assert "cves" in result[0]
    assert "cve_count" in result[0]
    assert result[0]["cve_count"] == 1
    assert result[0]["cves"][0]["cve_id"] == "CVE-2023-38408"


def test_enrich_empty_results():
    """Empty port list should return empty list"""
    result = enrich_scan_results([])
    assert result == []