"""
tests/test_correlation.py

Unit tests for correlation.py — alert grouping and incident pattern matching.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

import pytest
from correlation import correlate_alerts


# ── Helpers ────────────────────────────────────────────────────────────────────

def make_alert(rule_name, source_ip="10.0.0.1", username="root", risk_score=50, anomaly_level="high"):
    return {
        "rule_name":     rule_name,
        "source_ip":     source_ip,
        "username":      username,
        "risk_score":    risk_score,
        "anomaly_level": anomaly_level,
        "description":   f"Test alert for {rule_name}",
    }


# ── Empty input ────────────────────────────────────────────────────────────────

def test_empty_alerts_returns_empty():
    assert correlate_alerts([]) == []


# ── Single alert fallback ──────────────────────────────────────────────────────

def test_single_alert_creates_one_incident():
    alerts = [make_alert("brute_force_ssh")]
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 1


def test_single_alert_incident_title_contains_rule():
    alerts = [make_alert("brute_force_ssh")]
    incidents = correlate_alerts(alerts)
    assert "Brute Force Ssh" in incidents[0]["title"] or "brute_force_ssh" in incidents[0]["title"].lower()


def test_single_alert_carries_source_ip():
    alerts = [make_alert("sensitive_file_access", source_ip="192.168.1.5")]
    incidents = correlate_alerts(alerts)
    assert incidents[0]["source_ip"] == "192.168.1.5"


def test_single_alert_carries_username():
    alerts = [make_alert("sensitive_file_access", username="alice")]
    incidents = correlate_alerts(alerts)
    assert incidents[0]["username"] == "alice"


# ── Grouping by (ip, user) ─────────────────────────────────────────────────────

def test_same_ip_user_grouped_into_one_incident():
    alerts = [
        make_alert("brute_force_ssh",   source_ip="10.0.0.1", username="root"),
        make_alert("sensitive_file_access", source_ip="10.0.0.1", username="root"),
    ]
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 1


def test_different_ips_create_separate_incidents():
    alerts = [
        make_alert("brute_force_ssh", source_ip="10.0.0.1", username="root"),
        make_alert("brute_force_ssh", source_ip="10.0.0.2", username="root"),
    ]
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 2


def test_different_users_same_ip_create_separate_incidents():
    alerts = [
        make_alert("brute_force_ssh", source_ip="10.0.0.1", username="alice"),
        make_alert("brute_force_ssh", source_ip="10.0.0.1", username="bob"),
    ]
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 2


# ── Pattern: full compromise ───────────────────────────────────────────────────

def test_full_compromise_pattern_detected():
    alerts = [
        make_alert("brute_force_ssh",        source_ip="10.0.0.1", username="root"),
        make_alert("sudo_after_suspicious_login", source_ip="10.0.0.1", username="root"),
        make_alert("sensitive_file_access",  source_ip="10.0.0.1", username="root"),
    ]
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 1
    assert "Compromise" in incidents[0]["title"] or "compromise" in incidents[0]["title"].lower()


def test_full_compromise_has_all_rules_triggered():
    alerts = [
        make_alert("brute_force_ssh",         source_ip="10.0.0.1", username="root"),
        make_alert("sudo_after_suspicious_login", source_ip="10.0.0.1", username="root"),
        make_alert("sensitive_file_access",   source_ip="10.0.0.1", username="root"),
    ]
    incidents = correlate_alerts(alerts)
    rules = incidents[0]["rules_triggered"]
    assert "brute_force_ssh" in rules
    assert "sudo_after_suspicious_login" in rules
    assert "sensitive_file_access" in rules


# ── Pattern: SSH compromise (brute + privilege, no sensitive) ──────────────────

def test_ssh_compromise_pattern_detected():
    alerts = [
        make_alert("brute_force_ssh",         source_ip="10.0.0.1", username="root"),
        make_alert("sudo_after_suspicious_login", source_ip="10.0.0.1", username="root"),
    ]
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 1
    assert "SSH" in incidents[0]["title"] or "Privilege" in incidents[0]["title"]


# ── Pattern: sensitive access only ────────────────────────────────────────────

def test_sensitive_access_pattern_detected():
    alerts = [make_alert("sensitive_file_access", source_ip="10.0.0.1", username="alice")]
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 1
    assert "Sensitive" in incidents[0]["title"]


# ── Pattern: system anomaly ────────────────────────────────────────────────────

def test_system_anomaly_pattern_detected():
    alerts = [make_alert("system_service_anomaly", source_ip=None, username=None)]
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 1
    assert "System" in incidents[0]["title"] or "Anomaly" in incidents[0]["title"]


# ── Incident structure ─────────────────────────────────────────────────────────

def test_incident_has_required_fields():
    alerts = [make_alert("brute_force_ssh")]
    incident = correlate_alerts(alerts)[0]
    for field in ("title", "description", "source_ip", "username", "risk_score", "status", "alerts", "rules_triggered"):
        assert field in incident, f"Missing field: {field}"


def test_incident_status_is_open():
    alerts = [make_alert("brute_force_ssh")]
    incident = correlate_alerts(alerts)[0]
    assert incident["status"] == "open"


def test_incident_risk_score_is_max_of_alerts():
    alerts = [
        make_alert("brute_force_ssh",      risk_score=50),
        make_alert("sensitive_file_access", risk_score=70, source_ip="10.0.0.1", username="root"),
    ]
    incident = correlate_alerts(alerts)[0]
    assert incident["risk_score"] == 70


def test_incident_rules_triggered_is_sorted():
    alerts = [
        make_alert("sensitive_file_access", source_ip="10.0.0.1", username="root"),
        make_alert("brute_force_ssh",       source_ip="10.0.0.1", username="root"),
    ]
    incident = correlate_alerts(alerts)[0]
    rules = incident["rules_triggered"]
    assert rules == sorted(rules)


def test_incident_contains_contributing_alerts():
    alerts = [make_alert("brute_force_ssh")]
    incident = correlate_alerts(alerts)[0]
    assert len(incident["alerts"]) == 1
    assert incident["alerts"][0]["rule_name"] == "brute_force_ssh"


# ── Multiple distinct groups ───────────────────────────────────────────────────

def test_multiple_groups_produce_correct_count():
    alerts = [
        make_alert("brute_force_ssh",    source_ip="10.0.0.1", username="root"),
        make_alert("sensitive_file_access", source_ip="10.0.0.2", username="alice"),
        make_alert("system_service_anomaly", source_ip=None,    username=None),
    ]
    incidents = correlate_alerts(alerts)
    assert len(incidents) == 3
