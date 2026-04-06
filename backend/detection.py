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
    1.  brute_force_ssh           — ≥5 failed logins within window
    2.  invalid_user_enumeration  — ≥3 invalid user attempts
    3.  success_after_failures    — login success following failures
    4.  suspicious_login_time     — login between 10 PM and 6 AM
    5.  sudo_after_suspicious_login  — sudo after a brute-force/success_after_failures session
    6.  privilege_after_login     — sudo observed after login_success in same session
    7.  sensitive_file_access     — file_access / file_modified / sensitive_command events
    8.  system_service_anomaly    — service_failed / system_error / kernel OOM/panic events
    9.  port_scan_detected        — ≥5 blocked ports from same IP (UFW BLOCK)
    10. repeated_sudo_failures    — ≥3 failed sudo attempts (password abuse / privilege probing)
    11. new_user_created          — useradd/adduser executed via sudo
    12. cron_modification         — crontab or /etc/cron modified via sudo
"""

import logging
from typing import List, Dict, Any, Optional

from config import (
    EventType, Severity,
    BRUTE_FORCE_THRESHOLD,
    INVALID_USER_THRESHOLD,
    SUSPICIOUS_HOUR_START,
    SUSPICIOUS_HOUR_END,
    SUDO_FAILURE_THRESHOLD,
    PORT_SCAN_THRESHOLD,
)

# Patterns in cron command strings that indicate a reverse shell / C2 callback
_REVERSE_SHELL_INDICATORS = (
    "/dev/tcp", "/dev/udp",
    "bash -i", "sh -i",
    "nc ", "ncat ", "netcat ",
    "mkfifo", "python -c", "python3 -c",
    "perl -e", "ruby -rsocket",
    "socat ", "pty.spawn",
)

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# MITRE ATT&CK technique mappings per rule
# ──────────────────────────────────────────────
MITRE_MAPPING = {
    "brute_force_ssh": [
        {"id": "T1110",     "name": "Brute Force"},
        {"id": "T1110.001", "name": "Password Guessing"},
    ],
    "invalid_user_enumeration": [
        {"id": "T1589.001", "name": "Gather Victim Identity Information: Credentials"},
        {"id": "T1110.003", "name": "Password Spraying"},
    ],
    "success_after_failures": [
        {"id": "T1110",     "name": "Brute Force"},
        {"id": "T1078",     "name": "Valid Accounts"},
    ],
    "suspicious_login_time": [
        {"id": "T1078",     "name": "Valid Accounts"},
        {"id": "T1078.003", "name": "Local Accounts"},
    ],
    "sudo_after_suspicious_login": [
        {"id": "T1548.003", "name": "Abuse Elevation Control: Sudo and Sudo Caching"},
        {"id": "T1078",     "name": "Valid Accounts"},
    ],
    "privilege_after_login": [
        {"id": "T1548.003", "name": "Abuse Elevation Control: Sudo and Sudo Caching"},
        {"id": "T1548",     "name": "Abuse Elevation Control Mechanism"},
    ],
    "sensitive_file_access": [
        {"id": "T1005",     "name": "Data from Local System"},
        {"id": "T1552.001", "name": "Unsecured Credentials: Credentials In Files"},
    ],
    "system_service_anomaly": [
        {"id": "T1489",     "name": "Service Stop"},
        {"id": "T1543",     "name": "Create or Modify System Process"},
    ],
    "port_scan_detected": [
        {"id": "T1046",     "name": "Network Service Discovery"},
        {"id": "T1595.001", "name": "Active Scanning: Scanning IP Blocks"},
    ],
    "repeated_sudo_failures": [
        {"id": "T1548.003", "name": "Abuse Elevation Control: Sudo and Sudo Caching"},
        {"id": "T1110",     "name": "Brute Force"},
    ],
    "new_user_created": [
        {"id": "T1136.001", "name": "Create Account: Local Account"},
        {"id": "T1078",     "name": "Valid Accounts"},
    ],
    "cron_modification": [
        {"id": "T1053.003", "name": "Scheduled Task/Job: Cron"},
        {"id": "T1543",     "name": "Create or Modify System Process"},
    ],
    "ssh_login_success": [
        {"id": "T1078",     "name": "Valid Accounts"},
        {"id": "T1021.004", "name": "Remote Services: SSH"},
    ],
    "reverse_shell_cron": [
        {"id": "T1059.004", "name": "Command and Scripting Interpreter: Unix Shell"},
        {"id": "T1053.003", "name": "Scheduled Task/Job: Cron"},
        {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols"},
        {"id": "T1105",     "name": "Ingress Tool Transfer"},
    ],
}

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
        "rule_name":        rule_name,
        "severity":         severity,
        "risk_score":       risk_score,
        "description":      description,
        "source_ip":        session.get("source_ip"),
        "username":         session.get("username"),
        "session_key":      session.get("session_key", ""),
        "window_start":     session.get("window_start", ""),
        "window_end":       session.get("window_end", ""),
        "event_ids":        [],
        "session":          session,
        "mitre_techniques": MITRE_MAPPING.get(rule_name, []),
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
    Uses ip_invalid_user_count — the total invalid-user attempts from this IP
    across ALL sessions (including different fake usernames), so that
    ssh fakeuser1 / fakeuser2 / fakeuser3 all count toward the threshold.
    Base risk: 35
    """
    # Use cross-session IP total so different fake usernames accumulate
    count = session.get("ip_invalid_user_count", 0) or session.get("invalid_user_count", 0)
    if count < INVALID_USER_THRESHOLD:
        return None

    # Only fire on the session that actually has invalid_user events (avoid duplicate alerts)
    if session.get("invalid_user_count", 0) == 0:
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
        severity=Severity.CRITICAL,
        risk_score=80,
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
    Also fires when sudo is seen from an IP that had recent brute-force failures
    (cross-session detection for when hydra and manual SSH are in separate windows).
    Base risk: 85
    """
    has_sudo = session.get("sudo_count", 0) > 0
    if not has_sudo:
        return None

    is_suspicious_login = (
        session.get("failed_login_count", 0) >= BRUTE_FORCE_THRESHOLD
        or session.get("success_after_failures", False)
        or session.get("ip_had_recent_failures", False)  # cross-session flag
    )

    if not is_suspicious_login:
        return None

    description = (
        f"Sudo command executed in a session with suspicious login activity "
        f"for user '{session.get('username')}' from {session.get('source_ip')}. "
        f"Possible privilege escalation after credential compromise."
    )
    return _make_alert(
        rule_name="sudo_after_suspicious_login",
        severity=Severity.CRITICAL,
        risk_score=85,
        description=description,
        session=session,
    )


def rule_privilege_after_login(session: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Privilege escalation (sudo) immediately following a successful login.
    Fires when a session shows login_success followed by sudo in the same window,
    OR when sudo is seen after a successful login from an IP with recent failures.
    Base risk: 85
    """
    # In-session: sudo came after a login_success
    in_session = session.get("privilege_after_login", False)
    # Cross-session: successful login + sudo, IP had recent brute-force activity
    cross_session = (
        session.get("success_login_count", 0) > 0
        and session.get("sudo_count", 0) > 0
        and session.get("ip_had_recent_failures", False)
    )

    if not (in_session or cross_session):
        return None

    description = (
        f"Privilege escalation observed: sudo executed after "
        f"successful login for user '{session.get('username')}' from "
        f"{session.get('source_ip')}. "
        f"Review sudo commands for unauthorized actions."
    )
    return _make_alert(
        rule_name="privilege_after_login",
        severity=Severity.CRITICAL,
        risk_score=85,
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


def rule_port_scan_detected(session: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Port scan detection.
    Fires when ≥ PORT_SCAN_THRESHOLD distinct destination ports are blocked
    from the same source IP within the aggregation window (UFW BLOCK events).
    Base risk: 55
    """
    unique_ports = session.get("unique_ports_scanned", 0)
    if unique_ports < PORT_SCAN_THRESHOLD:
        return None

    count = session.get("port_scan_count", 0)
    description = (
        f"Port scan detected: {count} blocked connection attempt(s) across "
        f"{unique_ports} distinct port(s) from {session.get('source_ip')}. "
        f"Host is actively probing open services."
    )
    return _make_alert(
        rule_name="port_scan_detected",
        severity=Severity.HIGH,
        risk_score=65,
        description=description,
        session=session,
    )


def rule_repeated_sudo_failures(session: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Repeated sudo authentication failures.
    Fires when ≥ SUDO_FAILURE_THRESHOLD sudo failures occur in a session,
    indicating privilege escalation probing or password abuse.
    Base risk: 50
    """
    count = session.get("sudo_failure_count", 0)
    if count < SUDO_FAILURE_THRESHOLD:
        return None

    description = (
        f"{count} sudo authentication failure(s) for user '{session.get('username')}'. "
        f"Possible privilege escalation attempt or password abuse."
    )
    return _make_alert(
        rule_name="repeated_sudo_failures",
        severity=Severity.HIGH,
        risk_score=60,
        description=description,
        session=session,
    )


def rule_new_user_created(session: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    New local user account created via sudo (useradd / adduser / usermod).
    Fires when any new_user_created event appears in the session.
    Base risk: 70
    """
    if session.get("new_user_count", 0) == 0:
        return None

    # Extract the actual command from the event message for detail
    cmds = [
        e.get("message", "")
        for e in session.get("events", [])
        if e.get("event_type") == EventType.NEW_USER_CREATED
    ]
    detail = cmds[0][:120] if cmds else ""
    description = (
        f"New user account created or modified by '{session.get('username')}' via sudo. "
        f"Detail: {detail}"
    )
    return _make_alert(
        rule_name="new_user_created",
        severity=Severity.HIGH,
        risk_score=75,
        description=description,
        session=session,
    )


def rule_reverse_shell_cron(session: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Detects reverse shell or C2 callback commands executing via cron.
    Fires when a CRON_JOB event's command contains known reverse-shell patterns
    (e.g. /dev/tcp, bash -i, nc, mkfifo, python -c).
    This is always Critical — no legitimate cron job contains these patterns.
    Base risk: 95
    """
    shell_events = [
        e for e in session.get("events", [])
        if e.get("event_type") == EventType.CRON_JOB
        and any(ind in e.get("message", "").lower() for ind in _REVERSE_SHELL_INDICATORS)
    ]
    if not shell_events:
        return None

    cmd = shell_events[0].get("message", "")[:200]
    description = (
        f"REVERSE SHELL detected in cron job executed by '{session.get('username')}': "
        f"{cmd}. "
        f"Immediate incident response required — host is likely compromised."
    )
    return _make_alert(
        rule_name="reverse_shell_cron",
        severity=Severity.CRITICAL,
        risk_score=95,
        description=description,
        session=session,
    )


def rule_cron_modification(session: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Crontab or cron directory modified via sudo.
    Fires when any cron_modification event appears in the session,
    indicating possible persistence establishment.
    Base risk: 65
    """
    if session.get("cron_mod_count", 0) == 0:
        return None

    cmds = [
        e.get("message", "")
        for e in session.get("events", [])
        if e.get("event_type") == EventType.CRON_MODIFICATION
    ]
    detail = cmds[0][:120] if cmds else ""
    description = (
        f"Cron schedule modified by '{session.get('username')}' via sudo — "
        f"possible persistence mechanism. Detail: {detail}"
    )
    return _make_alert(
        rule_name="cron_modification",
        severity=Severity.HIGH,
        risk_score=70,
        description=description,
        session=session,
    )


def rule_ssh_login_success(session: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Any successful SSH login from an external/remote source.
    Fires a Low alert so every successful access is recorded, even without prior failures.
    Does NOT fire if success_after_failures already fired (that is a higher-severity alert).
    Base risk: 20
    """
    if session.get("success_login_count", 0) == 0:
        return None

    # Skip — success_after_failures rule will fire a more severe alert
    if session.get("success_after_failures", False):
        return None

    description = (
        f"Successful SSH login recorded for user '{session.get('username')}' "
        f"from {session.get('source_ip')}. "
        f"Verify this access was authorised."
    )
    return _make_alert(
        rule_name="ssh_login_success",
        severity=Severity.LOW,
        risk_score=20,
        description=description,
        session=session,
    )


# ──────────────────────────────────────────────
# Ordered rule registry
# Add new rules here — no other code needs to change.
# ──────────────────────────────────────────────
_RULES = [
    rule_reverse_shell_cron,        # Critical — checked first, highest priority
    rule_success_after_failures,
    rule_sudo_after_suspicious_login,
    rule_privilege_after_login,
    rule_new_user_created,
    rule_cron_modification,
    rule_brute_force_ssh,
    rule_repeated_sudo_failures,
    rule_port_scan_detected,
    rule_sensitive_file_access,
    rule_invalid_user_enumeration,
    rule_suspicious_login_time,
    rule_system_service_anomaly,
    rule_ssh_login_success,         # Low — checked last
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
