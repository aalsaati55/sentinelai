"""
test_detection.py

Unit tests for the rule-based detection engine.
Each rule is tested in isolation using hand-crafted session dicts.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

import pytest
from detection import (
    run_detection,
    rule_brute_force_ssh,
    rule_invalid_user_enumeration,
    rule_success_after_failures,
    rule_suspicious_login_time,
    rule_sudo_after_suspicious_login,
    rule_privilege_after_login,
    rule_sensitive_file_access,
    rule_system_service_anomaly,
)
from config import Severity, EventType


# ──────────────────────────────────────────────
# Session factory helpers
# ──────────────────────────────────────────────

def make_session(**kwargs):
    """Return a minimal session dict with sensible defaults."""
    defaults = {
        "session_key":            "1.2.3.4|testuser",
        "source_ip":              "1.2.3.4",
        "username":               "testuser",
        "window_start":           "2025-01-01T03:00:00",
        "window_end":             "2025-01-01T03:05:00",
        "activity_hour":          3,
        "events":                 [],
        "event_count":            1,
        "failed_login_count":     0,
        "success_login_count":    0,
        "invalid_user_count":     0,
        "sudo_count":             0,
        "custom_event_count":     0,
        "unique_usernames":       1,
        "event_rate":             1.0,
        "success_after_failures": False,
        "privilege_after_login":  False,
    }
    defaults.update(kwargs)
    return defaults


def make_event(event_type, hostname="host1"):
    return {"event_type": event_type, "hostname": hostname}


# ──────────────────────────────────────────────
# rule_brute_force_ssh
# ──────────────────────────────────────────────

class TestBruteForceSSH:
    def test_fires_at_threshold(self):
        s = make_session(failed_login_count=5)
        alert = rule_brute_force_ssh(s)
        assert alert is not None
        assert alert["rule_name"] == "brute_force_ssh"

    def test_fires_above_threshold(self):
        s = make_session(failed_login_count=10)
        assert rule_brute_force_ssh(s) is not None

    def test_no_fire_below_threshold(self):
        s = make_session(failed_login_count=4)
        assert rule_brute_force_ssh(s) is None

    def test_no_fire_zero(self):
        s = make_session(failed_login_count=0)
        assert rule_brute_force_ssh(s) is None

    def test_severity_is_high(self):
        s = make_session(failed_login_count=5)
        alert = rule_brute_force_ssh(s)
        assert alert["severity"] == Severity.HIGH

    def test_base_risk_score_30(self):
        s = make_session(failed_login_count=5)
        alert = rule_brute_force_ssh(s)
        assert alert["risk_score"] == 30

    def test_description_contains_count(self):
        s = make_session(failed_login_count=7)
        alert = rule_brute_force_ssh(s)
        assert "7" in alert["description"]

    def test_source_ip_propagated(self):
        s = make_session(failed_login_count=5, source_ip="10.0.0.1")
        alert = rule_brute_force_ssh(s)
        assert alert["source_ip"] == "10.0.0.1"


# ──────────────────────────────────────────────
# rule_invalid_user_enumeration
# ──────────────────────────────────────────────

class TestInvalidUserEnum:
    def test_fires_at_threshold(self):
        s = make_session(invalid_user_count=3)
        assert rule_invalid_user_enumeration(s) is not None

    def test_no_fire_below(self):
        s = make_session(invalid_user_count=2)
        assert rule_invalid_user_enumeration(s) is None

    def test_severity_medium(self):
        s = make_session(invalid_user_count=3)
        alert = rule_invalid_user_enumeration(s)
        assert alert["severity"] == Severity.MEDIUM

    def test_base_risk_20(self):
        s = make_session(invalid_user_count=3)
        assert rule_invalid_user_enumeration(s)["risk_score"] == 20


# ──────────────────────────────────────────────
# rule_success_after_failures
# ──────────────────────────────────────────────

class TestSuccessAfterFailures:
    def test_fires_when_flag_true(self):
        s = make_session(success_after_failures=True, failed_login_count=3)
        assert rule_success_after_failures(s) is not None

    def test_no_fire_when_flag_false(self):
        s = make_session(success_after_failures=False)
        assert rule_success_after_failures(s) is None

    def test_severity_high(self):
        s = make_session(success_after_failures=True, failed_login_count=3)
        assert rule_success_after_failures(s)["severity"] == Severity.HIGH

    def test_description_mentions_failures(self):
        s = make_session(success_after_failures=True, failed_login_count=5)
        desc = rule_success_after_failures(s)["description"]
        assert "5" in desc


# ──────────────────────────────────────────────
# rule_suspicious_login_time
# ──────────────────────────────────────────────

class TestSuspiciousLoginTime:
    def test_fires_at_2am(self):
        s = make_session(activity_hour=2, failed_login_count=1)
        assert rule_suspicious_login_time(s) is not None

    def test_fires_at_23(self):
        s = make_session(activity_hour=23, success_login_count=1)
        assert rule_suspicious_login_time(s) is not None

    def test_no_fire_at_noon_no_login(self):
        s = make_session(activity_hour=12)
        assert rule_suspicious_login_time(s) is None

    def test_no_fire_business_hours_with_login(self):
        s = make_session(activity_hour=10, failed_login_count=1)
        assert rule_suspicious_login_time(s) is None

    def test_no_fire_off_hours_no_login_activity(self):
        # Off-hours but no login events — only syslog/sudo
        s = make_session(activity_hour=2, failed_login_count=0, success_login_count=0)
        assert rule_suspicious_login_time(s) is None

    def test_base_risk_15(self):
        s = make_session(activity_hour=3, failed_login_count=1)
        assert rule_suspicious_login_time(s)["risk_score"] == 15


# ──────────────────────────────────────────────
# rule_sudo_after_suspicious_login
# ──────────────────────────────────────────────

class TestSudoAfterSuspiciousLogin:
    def test_fires_sudo_plus_brute_force(self):
        s = make_session(sudo_count=1, failed_login_count=5)
        assert rule_sudo_after_suspicious_login(s) is not None

    def test_fires_sudo_plus_success_after_failures(self):
        s = make_session(sudo_count=1, success_after_failures=True)
        assert rule_sudo_after_suspicious_login(s) is not None

    def test_no_fire_sudo_alone(self):
        s = make_session(sudo_count=1, failed_login_count=0, success_after_failures=False)
        assert rule_sudo_after_suspicious_login(s) is None

    def test_no_fire_brute_force_no_sudo(self):
        s = make_session(sudo_count=0, failed_login_count=6)
        assert rule_sudo_after_suspicious_login(s) is None

    def test_severity_high(self):
        s = make_session(sudo_count=1, failed_login_count=5)
        assert rule_sudo_after_suspicious_login(s)["severity"] == Severity.HIGH


# ──────────────────────────────────────────────
# rule_privilege_after_login
# ──────────────────────────────────────────────

class TestPrivilegeAfterLogin:
    def test_fires_when_flag_true(self):
        s = make_session(privilege_after_login=True)
        assert rule_privilege_after_login(s) is not None

    def test_no_fire_when_false(self):
        s = make_session(privilege_after_login=False)
        assert rule_privilege_after_login(s) is None

    def test_severity_high(self):
        s = make_session(privilege_after_login=True)
        assert rule_privilege_after_login(s)["severity"] == Severity.HIGH


# ──────────────────────────────────────────────
# rule_sensitive_file_access
# ──────────────────────────────────────────────

class TestSensitiveFileAccess:
    def test_fires_with_custom_events(self):
        events = [make_event(EventType.FILE_ACCESS), make_event(EventType.SENSITIVE_COMMAND)]
        s = make_session(custom_event_count=2, events=events)
        assert rule_sensitive_file_access(s) is not None

    def test_no_fire_zero_custom(self):
        s = make_session(custom_event_count=0, events=[])
        assert rule_sensitive_file_access(s) is None

    def test_severity_high(self):
        events = [make_event(EventType.FILE_MODIFIED)]
        s = make_session(custom_event_count=1, events=events)
        assert rule_sensitive_file_access(s)["severity"] == Severity.HIGH

    def test_description_lists_event_types(self):
        events = [make_event(EventType.FILE_ACCESS), make_event(EventType.NETWORK_ANOMALY)]
        s = make_session(custom_event_count=2, events=events)
        desc = rule_sensitive_file_access(s)["description"]
        assert "file_access" in desc or "network_anomaly" in desc


# ──────────────────────────────────────────────
# rule_system_service_anomaly
# ──────────────────────────────────────────────

class TestSystemServiceAnomaly:
    def test_fires_on_service_failed(self):
        events = [make_event(EventType.SERVICE_FAILED)]
        s = make_session(events=events)
        assert rule_system_service_anomaly(s) is not None

    def test_fires_on_system_error(self):
        events = [make_event(EventType.SYSTEM_ERROR)]
        s = make_session(events=events)
        assert rule_system_service_anomaly(s) is not None

    def test_no_fire_on_normal_events(self):
        events = [make_event(EventType.SERVICE_STARTED), make_event(EventType.CRON_JOB)]
        s = make_session(events=events)
        assert rule_system_service_anomaly(s) is None

    def test_severity_medium(self):
        events = [make_event(EventType.SERVICE_FAILED)]
        s = make_session(events=events)
        assert rule_system_service_anomaly(s)["severity"] == Severity.MEDIUM


# ──────────────────────────────────────────────
# run_detection (integration)
# ──────────────────────────────────────────────

class TestRunDetection:
    def test_empty_sessions_returns_empty(self):
        assert run_detection([]) == []

    def test_returns_list(self):
        result = run_detection([make_session()])
        assert isinstance(result, list)

    def test_multiple_rules_can_fire_on_same_session(self):
        """brute_force + success_after_failures should both fire."""
        s = make_session(
            failed_login_count=5,
            success_after_failures=True,
        )
        alerts = run_detection([s])
        rule_names = [a["rule_name"] for a in alerts]
        assert "brute_force_ssh" in rule_names
        assert "success_after_failures" in rule_names

    def test_all_alerts_have_required_fields(self):
        s = make_session(failed_login_count=5)
        alerts = run_detection([s])
        for a in alerts:
            for field in ("rule_name", "severity", "risk_score", "description",
                          "session_key", "window_start", "window_end"):
                assert field in a, f"Missing field '{field}' in alert"

    def test_rule_error_does_not_crash(self):
        """A session missing keys should not raise; the engine catches errors."""
        bad_session = {}
        result = run_detection([bad_session])
        assert isinstance(result, list)
