"""
correlation.py

Incident correlation engine.
Groups related alerts into incidents based on:
    - shared source_ip / username (same attacker)
    - rule combination patterns (e.g. brute_force + success + sudo)

Incident dict structure:
{
    "title":         str   — human-readable incident title
    "description":   str   — what happened, which rules fired, why it's significant
    "source_ip":     str | None
    "username":      str | None
    "risk_score":    int   — highest risk_score among contributing alerts
    "anomaly_level": str | None — set after ML scoring
    "status":        str   — "open"
    "alerts":        list  — contributing alert dicts
    "rules_triggered": list — sorted list of rule_names that fired
}

Correlation patterns (evaluated in priority order):
    1. full_compromise   — brute_force/success_after_failures + privilege + sensitive_file
    2. ssh_compromise    — brute_force/success_after_failures + privilege escalation
    3. brute_force_only  — brute_force + success_after_failures (no privilege yet)
    4. privilege_abuse   — sudo/privilege alerts without prior suspicious login
    5. sensitive_access  — only sensitive_file_access or network_anomaly alerts
    6. system_anomaly    — only system_service_anomaly alerts
    7. single_alert      — any alert that didn't match a multi-rule pattern
"""

import logging
from collections import defaultdict
from typing import List, Dict, Any, Set

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Rule name sets used in pattern matching
# ──────────────────────────────────────────────
_BRUTE_RULES       = {"brute_force_ssh", "invalid_user_enumeration", "success_after_failures"}
_PRIVILEGE_RULES   = {"sudo_after_suspicious_login", "privilege_after_login"}
_SENSITIVE_RULES   = {"sensitive_file_access"}
_SYSTEM_RULES      = {"system_service_anomaly"}
_TIME_RULES        = {"suspicious_login_time"}


# ──────────────────────────────────────────────
# Incident title/description builder
# ──────────────────────────────────────────────

def _build_incident(
    title: str,
    description: str,
    alerts: List[Dict[str, Any]],
    source_ip=None,
    username=None,
) -> Dict[str, Any]:
    rules_triggered = sorted({a["rule_name"] for a in alerts})
    risk_score      = max((a.get("risk_score", 0) for a in alerts), default=0)

    return {
        "title":           title,
        "description":     description,
        "source_ip":       source_ip,
        "username":        username,
        "risk_score":      risk_score,
        "anomaly_level":   None,   # filled in by anomaly_scoring
        "status":          "open",
        "alerts":          alerts,
        "rules_triggered": rules_triggered,
    }


# ──────────────────────────────────────────────
# Pattern matchers
# Each takes a set of rule names and a list of alerts for that group.
# Returns an incident dict or None if pattern doesn't match.
# ──────────────────────────────────────────────

def _pattern_full_compromise(
    rules: Set[str], alerts: List[Dict[str, Any]],
    ip: str, user: str
) -> Dict[str, Any] | None:
    """
    Full compromise chain:
    brute-force / success-after-failures  +  privilege escalation  +  sensitive file access
    This is the most severe scenario — attacker got in, escalated, and accessed sensitive data.
    """
    has_brute     = bool(rules & _BRUTE_RULES)
    has_privilege = bool(rules & _PRIVILEGE_RULES)
    has_sensitive = bool(rules & _SENSITIVE_RULES)

    if not (has_brute and has_privilege and has_sensitive):
        return None

    return _build_incident(
        title="Possible Full System Compromise",
        description=(
            f"A full attack chain was detected for user '{user}' from {ip}. "
            f"Rules triggered: {sorted(rules & (_BRUTE_RULES | _PRIVILEGE_RULES | _SENSITIVE_RULES))}. "
            f"The attacker appears to have gained access via SSH brute force or credential stuffing, "
            f"escalated privileges using sudo, and then accessed or modified sensitive files. "
            f"Immediate investigation required."
        ),
        alerts=alerts,
        source_ip=ip,
        username=user,
    )


def _pattern_ssh_compromise(
    rules: Set[str], alerts: List[Dict[str, Any]],
    ip: str, user: str
) -> Dict[str, Any] | None:
    """
    SSH compromise with privilege escalation, but no sensitive file access yet.
    """
    has_brute     = bool(rules & _BRUTE_RULES)
    has_privilege = bool(rules & _PRIVILEGE_RULES)
    has_sensitive = bool(rules & _SENSITIVE_RULES)

    if not (has_brute and has_privilege) or has_sensitive:
        return None

    return _build_incident(
        title="Possible SSH Compromise with Privilege Escalation",
        description=(
            f"Suspicious login activity followed by privilege escalation detected "
            f"for user '{user}' from {ip}. "
            f"Rules triggered: {sorted(rules & (_BRUTE_RULES | _PRIVILEGE_RULES))}. "
            f"Attacker may have successfully authenticated after brute force and "
            f"escalated to root via sudo."
        ),
        alerts=alerts,
        source_ip=ip,
        username=user,
    )


def _pattern_brute_force_success(
    rules: Set[str], alerts: List[Dict[str, Any]],
    ip: str, user: str
) -> Dict[str, Any] | None:
    """
    Brute force with successful login, no privilege escalation detected yet.
    """
    has_success   = "success_after_failures" in rules
    has_brute     = "brute_force_ssh" in rules or "invalid_user_enumeration" in rules
    has_privilege = bool(rules & _PRIVILEGE_RULES)

    if not (has_brute or has_success) or has_privilege:
        return None
    if not (has_brute and has_success):
        return None

    return _build_incident(
        title="Brute Force Attack — Possible Credential Compromise",
        description=(
            f"A brute force attack was detected against user '{user}' from {ip}, "
            f"followed by a successful login. "
            f"Rules triggered: {sorted(rules & _BRUTE_RULES)}. "
            f"The attacker may have guessed valid credentials. "
            f"Check for further activity from this source IP."
        ),
        alerts=alerts,
        source_ip=ip,
        username=user,
    )


def _pattern_privilege_abuse(
    rules: Set[str], alerts: List[Dict[str, Any]],
    ip: str, user: str
) -> Dict[str, Any] | None:
    """
    Privilege escalation without prior suspicious login — insider threat or
    compromised legitimate account.
    """
    has_privilege = bool(rules & _PRIVILEGE_RULES)
    has_brute     = bool(rules & _BRUTE_RULES)

    if not has_privilege or has_brute:
        return None

    return _build_incident(
        title="Suspicious Privilege Escalation",
        description=(
            f"Privilege escalation (sudo) detected for user '{user}' from {ip} "
            f"without prior brute force activity. "
            f"Rules triggered: {sorted(rules & _PRIVILEGE_RULES)}. "
            f"This may indicate an insider threat or an already-compromised account."
        ),
        alerts=alerts,
        source_ip=ip,
        username=user,
    )


def _pattern_sensitive_access(
    rules: Set[str], alerts: List[Dict[str, Any]],
    ip: str, user: str
) -> Dict[str, Any] | None:
    """Sensitive file / command events without escalation."""
    if not (rules & _SENSITIVE_RULES):
        return None

    return _build_incident(
        title="Sensitive File or Command Activity Detected",
        description=(
            f"Sensitive security events detected for user '{user}' from {ip}. "
            f"Rules triggered: {sorted(rules & _SENSITIVE_RULES)}. "
            f"Sensitive files may have been accessed or modified, or dangerous "
            f"commands were executed. Review custom security log entries."
        ),
        alerts=alerts,
        source_ip=ip,
        username=user,
    )


def _pattern_system_anomaly(
    rules: Set[str], alerts: List[Dict[str, Any]],
    ip: str, user: str
) -> Dict[str, Any] | None:
    """System-level anomalies (service failures, kernel errors)."""
    if not (rules & _SYSTEM_RULES):
        return None

    return _build_incident(
        title="System / Service Anomaly Detected",
        description=(
            f"System-level anomalies detected on the monitored host. "
            f"Rules triggered: {sorted(rules & _SYSTEM_RULES)}. "
            f"Service failures or kernel-level errors were observed — "
            f"this may indicate system instability or tampering."
        ),
        alerts=alerts,
        source_ip=ip,
        username=user,
    )


def _pattern_single_alert(
    rules: Set[str], alerts: List[Dict[str, Any]],
    ip: str, user: str
) -> Dict[str, Any]:
    """Fallback: create a single-alert incident for any unmatched alert."""
    rule = next(iter(rules))
    a    = alerts[0]
    return _build_incident(
        title=f"Security Alert: {rule.replace('_', ' ').title()}",
        description=a.get("description", f"Alert triggered by rule: {rule}."),
        alerts=alerts,
        source_ip=ip,
        username=user,
    )


# Priority-ordered pattern list
_PATTERNS = [
    _pattern_full_compromise,
    _pattern_ssh_compromise,
    _pattern_brute_force_success,
    _pattern_privilege_abuse,
    _pattern_sensitive_access,
    _pattern_system_anomaly,
]


# ──────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────

def correlate_alerts(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Group related alerts into incidents.

    Alerts are first grouped by (source_ip, username). Within each group,
    we try each pattern in priority order. The first matching pattern wins
    and produces one incident for that group.

    Returns a list of incident dicts.
    """
    if not alerts:
        return []

    # Group alerts by (source_ip, username)
    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for alert in alerts:
        ip   = alert.get("source_ip") or "unknown_ip"
        user = alert.get("username")  or "unknown_user"
        key  = f"{ip}|{user}"
        groups[key].append(alert)

    incidents: List[Dict[str, Any]] = []

    for key, group_alerts in groups.items():
        ip, user = key.split("|", 1)
        ip   = ip   if ip   != "unknown_ip"   else None
        user = user if user != "unknown_user" else None

        rules = {a["rule_name"] for a in group_alerts}

        # Try patterns in priority order
        matched = False
        for pattern_fn in _PATTERNS:
            incident = pattern_fn(rules, group_alerts, ip, user)
            if incident is not None:
                incidents.append(incident)
                matched = True
                break

        # Fallback: one incident per unmatched alert
        if not matched:
            for alert in group_alerts:
                incidents.append(
                    _pattern_single_alert({alert["rule_name"]}, [alert], ip, user)
                )

    logger.info(f"Correlation complete: {len(incidents)} incidents from {len(alerts)} alerts.")
    return incidents
