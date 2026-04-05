"""
detection.py

Rule-based detection engine.
Operates on aggregated session dicts produced by aggregator.py.
Each rule function inspects a session and returns an alert dict or None.

Alert dict structure:
{
    "rule_name":     str   — machine-readable rule identifier
    "severity":      str   — Severity constant
    "risk_score":    int   — base score before correlation/ML bonus
    "description":   str   — human-readable explanation (shown in dashboard)
    "source_ip":     str | None
    "username":      str | None
    "session_key":   str
    "window_start":  str
    "window_end":    str
    "event_ids":     list  — DB ids of contributing events (populated after storage)
    "session":       dict  — reference to the full session for correlation
}

Rules implemented:
    1. brute_force_ssh           — ≥5 failed logins within window
    2. invalid_user_enumeration  — ≥3 invalid user attempts
    3. success_after_failures    — login success following failures
    4. suspicious_login_time     — login between 10 PM and 6 AM
    5. sudo_after_suspicious_login  — sudo after a brute-force/success_after_failures session
    6. privilege_after_login     — sudo observed after login_success in same session
    7. sensitive_file_access     — file_access / file_modified / sensitive_command events
    8. system_service_anomaly    — service_failed / system_error / kernel OOM/panic events
"""

import logging
from typing import List, Dict, Any, Optional

from config import (
    EventType, Severity,
    BRUTE_FORCE_THRESHOLD,
    INVALID_USER_THRESHOLD,
    SUSPICIOUS_HOUR_START,
    SUSPICIOUS_HOUR_END,
)

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Alert builder helper
# ──────────────────────────────────────────────

def _make_alert(
    rule_name: str,
    severity: str,
    risk_score: int,
    description: str,
    session: Dict[str, Any],
) -> Dict[str, Any]:
    """Construct a standardised alert dict from a session."""
    return {
        "rule_name":    rule_name,
        "severity":     severity,
        "risk_score":   risk_score,
        "description":  description,
        "source_ip":    session.get("source_ip"),
        "username":     session.get("username"),
        "session_key":  session.get("session_key", ""),
        "window_start": session.get("window_start", ""),
        "window_end":   session.get("window_end", ""),
        "event_ids":    [],       # populated after events are stored in DB
        "session":      session,  # kept for correlation stage
    }


# ──────────────────────────────────────────────
# Rule functions
# Each takes a session dict and returns an alert dict or None.
# ──────────────────────────────────────────────

def rule_brute_force_ssh(session: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Brute force SSH detection.
    Fires when a single (IP, user) session has ≥ BRUTE_FORCE_THRESHOLD
    failed login attempts within the aggregation window.
    Base risk: 30
    """
    count = session.get("failed_login_count", 0)
    if count < BRUTE_FORCE_THRESHOLD:
        return None

    description = (
        f"Brute force SSH attack detected: {count} failed login attempts "
        f"for user '{session.get('username')}' from {session.get('source_ip')} "
        f"within a {round((count / max(session.get('event_rate', 1), 0.01))):,}s window."
    )
    return _make_alert(
        rule_name="brute_force_ssh",
        severity=Severity.HIGH,
        risk_score=65,
        description=description,
        session=session,
    )


def rule_invalid_user_enumeration(session: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Invalid user enumeration detection.
    Fires when ≥ INVALID_USER_THRESHOLD invalid-user login attempts are seen
    in the same session, indicating username guessing / enumeration.
    Base risk: 20
    """
    count = session.get("invalid_user_count", 0)
    if count < INVALID_USER_THRESHOLD:
        return None

    description = (
        f"User enumeration detected: {count} attempts with non-existent usernames "
        f"from {session.get('source_ip')}. "
        f"Attacker may be probing valid account names."
    )
    return _make_alert(
        rule_name="invalid_user_enumeration",
        severity=Severity.MEDIUM,
        risk_score=35,
        description=description,
        session=session,
    )


def rule_success_after_failures(session: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Login success following repeated failures.
    Fires when a session has both failed logins AND a subsequent success —
    a strong indicator of a successful brute force compromise.
    Base risk: 30
    """
    if not session.get("success_after_failures"):
        return None

    failures = session.get("failed_login_count", 0)
    description = (
        f"Successful login after {failures} failed attempt(s) for user "
        f"'{session.get('username')}' from {session.get('source_ip')}. "
        f"Possible brute force success or credential stuffing."
    )
    return _make_alert(
        rule_name="success_after_failures",
        severity=Severity.HIGH,
        risk_score=75,
        description=description,
        session=session,
    )


def rule_suspicious_login_time(session: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Login during off-hours (10 PM – 6 AM).
    Fires when a successful or attempted login is recorded during
    suspicious hours, which may indicate unauthorized access.
    Base risk: 15
    """
    hour = session.get("activity_hour", 12)
    is_suspicious = (hour >= SUSPICIOUS_HOUR_START) or (hour < SUSPICIOUS_HOUR_END)

    if not is_suspicious:
        return None

    # Only fire if there was actual login activity (not just sessions/sudo)
    login_activity = (
        session.get("failed_login_count", 0) +
        session.get("success_login_count", 0)
    )
    if login_activity == 0:
        return None

    description = (
        f"Login activity detected at suspicious hour ({hour:02d}:xx) "
        f"for user '{session.get('username')}' from {session.get('source_ip')}. "
        f"Off-hours access may indicate unauthorized use."
    )
    return _make_alert(
        rule_name="suspicious_login_time",
        severity=Severity.MEDIUM,
        risk_score=35,
        description=description,
        session=session,
    )


def rule_sudo_after_suspicious_login(session: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Sudo usage in a session that also triggered brute force or success-after-failures.
    Fires when a session has both suspicious login patterns AND sudo activity,
    suggesting an attacker gaining root access after compromising credentials.
    Base risk: 20
    """
    has_sudo = session.get("sudo_count", 0) > 0
    is_suspicious_login = (
        session.get("failed_login_count", 0) >= BRUTE_FORCE_THRESHOLD
        or session.get("success_after_failures", False)
    )

    if not (has_sudo and is_suspicious_login):
        return None

    description = (
        f"Sudo command executed in a session with suspicious login activity "
        f"for user '{session.get('username')}' from {session.get('source_ip')}. "
        f"Possible privilege escalation after credential compromise."
    )
    return _make_alert(
        rule_name="sudo_after_suspicious_login",
        severity=Severity.HIGH,
        risk_score=80,
        description=description,
        session=session,
    )


def rule_privilege_after_login(session: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Privilege escalation (sudo) immediately following a successful login.
    Fires when a session shows login_success followed by sudo in the same window.
    Base risk: 20
    """
    if not session.get("privilege_after_login"):
        return None

    description = (
        f"Privilege escalation observed: sudo executed immediately after "
        f"successful login for user '{session.get('username')}' from "
        f"{session.get('source_ip')}. "
        f"Review sudo commands for unauthorized actions."
    )
    return _make_alert(
        rule_name="privilege_after_login",
        severity=Severity.HIGH,
        risk_score=80,
        description=description,
        session=session,
    )


def rule_sensitive_file_access(session: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Sensitive file or command activity from the custom security log.
    Fires when a session contains file_access, file_modified, sensitive_command,
    network_anomaly, or custom_alert events.
    Base risk: 25
    """
    count = session.get("custom_event_count", 0)
    if count == 0:
        return None

    # Collect event types seen for the description
    custom_types = set()
    for e in session.get("events", []):
        et = e.get("event_type", "")
        if et in {
            EventType.FILE_ACCESS, EventType.FILE_MODIFIED,
            EventType.SENSITIVE_COMMAND, EventType.NETWORK_ANOMALY,
            EventType.CUSTOM_ALERT,
        }:
            custom_types.add(et)

    type_str = ", ".join(sorted(custom_types))
    description = (
        f"Sensitive security event(s) detected for user '{session.get('username')}' "
        f"from {session.get('source_ip')}: {count} event(s) of type [{type_str}]. "
        f"Inspect raw logs for details."
    )
    return _make_alert(
        rule_name="sensitive_file_access",
        severity=Severity.HIGH,
        risk_score=70,
        description=description,
        session=session,
    )


def rule_system_service_anomaly(session: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    System or service anomaly from syslog.
    Fires when a session (keyed to unknown_ip/unknown_user — syslog events)
    contains service_failed or system_error events that may indicate instability
    or an attacker disrupting services.
    Base risk: 15
    """
    anomaly_types = {EventType.SERVICE_FAILED, EventType.SYSTEM_ERROR}
    anomaly_events = [
        e for e in session.get("events", [])
        if e.get("event_type") in anomaly_types
    ]
    if not anomaly_events:
        return None

    count     = len(anomaly_events)
    hostname  = anomaly_events[0].get("hostname", "unknown")
    type_str  = ", ".join({e["event_type"] for e in anomaly_events})
    description = (
        f"{count} system anomaly event(s) detected on host '{hostname}': "
        f"[{type_str}]. "
        f"Service failures or kernel errors may indicate instability or tampering."
    )
    return _make_alert(
        rule_name="system_service_anomaly",
        severity=Severity.MEDIUM,
        risk_score=15,
        description=description,
        session=session,
    )


# ──────────────────────────────────────────────
# Ordered rule registry
# Add new rules here — no other code needs to change.
# ──────────────────────────────────────────────
_RULES = [
    rule_brute_force_ssh,
    rule_invalid_user_enumeration,
    rule_success_after_failures,
    rule_suspicious_login_time,
    rule_sudo_after_suspicious_login,
    rule_privilege_after_login,
    rule_sensitive_file_access,
    rule_system_service_anomaly,
]


# ──────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────

def run_detection(sessions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Run all detection rules against every aggregated session.

    Each rule is applied to every session independently — a single session
    can trigger multiple rules (e.g., brute_force + success_after_failures).

    Returns a flat list of alert dicts.
    """
    alerts: List[Dict[str, Any]] = []

    for session in sessions:
        for rule_fn in _RULES:
            try:
                alert = rule_fn(session)
                if alert is not None:
                    alerts.append(alert)
                    logger.debug(
                        f"[{alert['rule_name']}] fired on session "
                        f"[{session.get('session_key')}] — "
                        f"severity={alert['severity']} risk={alert['risk_score']}"
                    )
            except Exception as e:
                logger.error(f"Rule {rule_fn.__name__} raised an error: {e}")

    logger.info(f"Detection complete: {len(alerts)} alerts from {len(sessions)} sessions.")
    return alerts
