"""
risk_scoring.py

Calculates a final risk score (0–100) for each alert and incident by combining:
    - base score from the detection rule
    - correlation bonus  (multiple distinct rule categories fired for the same actor)
    - anomaly level bonus (from Isolation Forest ML scoring)

Score bands:
    0–29   → Low
    30–59  → Medium
    60–79  → High
    80–100 → Critical

Scoring formula
---------------
For an ALERT:
    score = rule_base_score + time_bonus + anomaly_bonus
    capped at 100

For an INCIDENT:
    score = max(alert_base_scores) + correlation_bonus + anomaly_bonus
    capped at 100

Bonuses
-------
    suspicious_login_time rule      → +10
    correlation_bonus per extra rule category beyond the first:
        e.g. brute_force + privilege  → +15
             brute_force + privilege + sensitive → +25
    anomaly_level = medium          → +10
    anomaly_level = high            → +20
"""

import logging
from typing import Dict, Any, List

from config import (
    Severity,
    RISK_LOW_MAX, RISK_MEDIUM_MAX, RISK_CRITICAL_MIN,
)
from utils import clamp

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Per-rule score ceilings — prevent anomaly bonus from pushing
# informational/medium rules into a higher severity band
# ──────────────────────────────────────────────
_RULE_SCORE_CEILING: Dict[str, int] = {
    # Low ceiling — these are informational, anomaly bonus must not escalate them
    "ssh_login_success":        29,
    "system_service_anomaly":   29,
    # Medium ceiling — reconnaissance / low-threat activity
    "suspicious_login_time":    59,
    "invalid_user_enumeration": 59,
    # High ceiling — real threats but not yet confirmed compromise
    "port_scan_detected":       79,
    "repeated_sudo_failures":   79,
    # No ceiling for Critical rules — they can only go up
    # reverse_shell_cron, success_after_failures, privilege_after_login,
    # sudo_after_suspicious_login, new_user_created are uncapped
}

# ──────────────────────────────────────────────
# Rule category buckets for correlation bonus
# ──────────────────────────────────────────────
_CATEGORY_BRUTE     = {"brute_force_ssh", "invalid_user_enumeration", "success_after_failures"}
_CATEGORY_PRIVILEGE = {"sudo_after_suspicious_login", "privilege_after_login"}
_CATEGORY_SENSITIVE = {"sensitive_file_access"}
_CATEGORY_SYSTEM    = {"system_service_anomaly"}
_CATEGORY_TIME      = {"suspicious_login_time"}

_CATEGORIES = [_CATEGORY_BRUTE, _CATEGORY_PRIVILEGE, _CATEGORY_SENSITIVE,
               _CATEGORY_SYSTEM, _CATEGORY_TIME]


def _anomaly_bonus(anomaly_level: str | None) -> int:
    if anomaly_level == "high":
        return 20
    if anomaly_level == "medium":
        return 10
    return 0


def _correlation_bonus(rules_triggered: List[str]) -> int:
    """
    Award a bonus based on how many distinct rule categories fired.
    More categories = more attack-chain coverage = higher urgency.
    """
    rule_set = set(rules_triggered)
    categories_hit = sum(1 for cat in _CATEGORIES if rule_set & cat)
    if categories_hit >= 3:
        return 25
    if categories_hit == 2:
        return 15
    return 0


def _time_bonus(rules_triggered: List[str]) -> int:
    """Extra +10 if suspicious_login_time fired (off-hours access)."""
    return 10 if "suspicious_login_time" in rules_triggered else 0


# ──────────────────────────────────────────────
# Public API: score an alert
# ──────────────────────────────────────────────

def score_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich an alert dict with a final risk_score and severity.

    Reads:
        alert["risk_score"]    — base score set by detection rule
        alert["rule_name"]     — rule that fired
        alert["anomaly_level"] — set by anomaly_scoring (may be None)

    Writes (in-place and returns):
        alert["risk_score"]    — final capped score
        alert["severity"]      — derived severity label
        alert["score_breakdown"] — dict explaining how the score was calculated
    """
    base          = alert.get("risk_score", 0)
    anomaly_level = alert.get("anomaly_level")
    rule_name     = alert.get("rule_name", "")

    time_b    = _time_bonus([rule_name])
    anomaly_b = _anomaly_bonus(anomaly_level)
    total     = clamp(base + time_b + anomaly_b)

    # Apply per-rule ceiling to prevent anomaly bonus from escalating severity
    ceiling = _RULE_SCORE_CEILING.get(rule_name)
    if ceiling is not None:
        total = min(total, ceiling)

    alert["risk_score"]      = total
    alert["severity"]        = score_to_severity(total)
    alert["score_breakdown"] = {
        "base_score":     base,
        "time_bonus":     time_b,
        "anomaly_bonus":  anomaly_b,
        "total":          total,
    }
    return alert


# ──────────────────────────────────────────────
# Public API: score an incident
# ──────────────────────────────────────────────

def score_incident(incident: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich an incident dict with a final risk_score and severity.

    Reads:
        incident["alerts"]          — list of contributing alert dicts
        incident["rules_triggered"] — list of rule names
        incident["anomaly_level"]   — set by anomaly_scoring (may be None)

    Writes (in-place and returns):
        incident["risk_score"]      — final capped score
        incident["severity"]        — derived severity label
        incident["score_breakdown"] — dict explaining the score
    """
    alerts         = incident.get("alerts", [])
    rules          = incident.get("rules_triggered", [])
    anomaly_level  = incident.get("anomaly_level")

    # Base = highest alert base score in the group
    base = max((a.get("risk_score", 0) for a in alerts), default=0)

    corr_b    = _correlation_bonus(rules)
    time_b    = _time_bonus(rules)
    anomaly_b = _anomaly_bonus(anomaly_level)
    total     = clamp(base + corr_b + time_b + anomaly_b)

    incident["risk_score"]      = total
    incident["severity"]        = score_to_severity(total)
    incident["score_breakdown"] = {
        "base_score":         base,
        "correlation_bonus":  corr_b,
        "time_bonus":         time_b,
        "anomaly_bonus":      anomaly_b,
        "total":              total,
    }
    return incident


# ──────────────────────────────────────────────
# Utility
# ──────────────────────────────────────────────

def score_to_severity(score: int) -> str:
    """Map a numeric risk score (0–100) to a severity label."""
    if score <= RISK_LOW_MAX:
        return Severity.LOW
    elif score <= RISK_MEDIUM_MAX:
        return Severity.MEDIUM
    elif score <= RISK_CRITICAL_MIN - 1:
        return Severity.HIGH
    else:
        return Severity.CRITICAL
