"""
routers/tuning.py

GET    /api/tuning/thresholds              — list all tunable rule thresholds (with defaults)
POST   /api/tuning/thresholds              — set / override a threshold
DELETE /api/tuning/thresholds/{rule_name}  — reset a threshold back to default
GET    /api/tuning/rules                   — list all known rule names + current effective threshold
PATCH  /api/incidents/{id}/false-positive  — mark/unmark incident as false positive
"""

import logging
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional

from storage import (
    get_rule_thresholds, set_rule_threshold, delete_rule_threshold,
    mark_incident_false_positive, add_audit_log,
)
from auth import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(tags=["tuning"])

# ── Default thresholds (mirrors config.py) ────────────────────
RULE_DEFAULTS = {
    "brute_force_ssh":         {"threshold": 5,  "label": "Brute Force SSH",               "description": "Failed login attempts before alert fires"},
    "invalid_user_enumeration":{"threshold": 4,  "label": "Invalid User Enumeration",      "description": "Distinct invalid usernames from same IP"},
    "repeated_sudo_failures":  {"threshold": 5,  "label": "Repeated Sudo Failures",        "description": "sudo password failures before alert"},
    "port_scan_detected":      {"threshold": 10, "label": "Port Scan Detected",            "description": "Distinct blocked ports from same IP"},
    "suspicious_login_time":   {"threshold": 22, "label": "Suspicious Login Hour (start)", "description": "Hour (0-23) — logins after this hour are flagged"},
}

# ── Event-based rules (no numeric threshold — suppress only) ──
EVENT_RULES = {
    "success_after_failures":      {"label": "Success After Failures",      "description": "Login success after repeated failures — possible brute-force compromise"},
    "sudo_after_suspicious_login": {"label": "Sudo After Suspicious Login", "description": "Privilege escalation in a session with prior brute-force activity"},
    "privilege_after_login":       {"label": "Privilege After Login",       "description": "sudo used immediately after login_success in same session"},
    "sensitive_file_access":       {"label": "Sensitive File Access",       "description": "file_access, file_modified, sensitive_command or network_anomaly events detected"},
    "system_service_anomaly":      {"label": "System / Service Anomaly",    "description": "service_failed or system_error events in syslog — instability or tampering"},
    "new_user_created":            {"label": "New User Created",            "description": "useradd / adduser executed via sudo — possible persistence"},
    "reverse_shell_cron":          {"label": "Reverse Shell via Cron",      "description": "Cron job containing reverse-shell or C2 callback indicators"},
    "cron_modification":           {"label": "Cron Modification",           "description": "crontab or /etc/cron* modified via sudo"},
    "ssh_login_success":           {"label": "SSH Login Success",           "description": "Any successful SSH login from an external source (low severity)"},
}

TUNABLE_RULES = list(RULE_DEFAULTS.keys())


# ── Schemas ───────────────────────────────────────────────────

class ThresholdSet(BaseModel):
    rule_name: str
    threshold: int


class IncidentFPRequest(BaseModel):
    false_positive: bool
    reason: Optional[str] = ""


# ── Endpoints ─────────────────────────────────────────────────

@router.get("/api/tuning/rules")
def list_rules(current_user: dict = Depends(get_current_user)):
    """Return all known rules — threshold-tunable ones first, then event-based suppress-only."""
    overrides = {r["rule_name"]: r["threshold"] for r in get_rule_thresholds()}
    result = []
    for rule_name, meta in RULE_DEFAULTS.items():
        result.append({
            "rule_name":   rule_name,
            "label":       meta["label"],
            "description": meta["description"],
            "default":     meta["threshold"],
            "threshold":   overrides.get(rule_name, meta["threshold"]),
            "overridden":  rule_name in overrides,
            "tunable":     True,
        })
    for rule_name, meta in EVENT_RULES.items():
        result.append({
            "rule_name":   rule_name,
            "label":       meta["label"],
            "description": meta["description"],
            "default":     None,
            "threshold":   None,
            "overridden":  False,
            "tunable":     False,
        })
    return result


@router.get("/api/tuning/thresholds")
def list_thresholds(current_user: dict = Depends(get_current_user)):
    return get_rule_thresholds()


@router.post("/api/tuning/thresholds", status_code=201)
def save_threshold(body: ThresholdSet, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    if body.rule_name not in TUNABLE_RULES:
        raise HTTPException(status_code=400, detail=f"Unknown tunable rule: {body.rule_name}")
    if body.threshold < 1 or body.threshold > 9999:
        raise HTTPException(status_code=400, detail="Threshold must be between 1 and 9999")
    row = set_rule_threshold(body.rule_name, body.threshold, current_user["username"])
    add_audit_log(current_user["username"], "threshold_set", "rule", None,
                  f"{body.rule_name} threshold → {body.threshold}")
    logger.info(f"Threshold set: {body.rule_name} = {body.threshold} by {current_user['username']}")
    return row


@router.delete("/api/tuning/thresholds/{rule_name}", status_code=200)
def reset_threshold(rule_name: str, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    delete_rule_threshold(rule_name)
    add_audit_log(current_user["username"], "threshold_reset", "rule", None,
                  f"{rule_name} reset to default")
    return {"detail": "Reset to default", "rule_name": rule_name}


@router.patch("/api/incidents/{incident_id}/false-positive")
def incident_false_positive(incident_id: int, body: IncidentFPRequest, current_user: dict = Depends(get_current_user)):
    row = mark_incident_false_positive(incident_id, body.false_positive, body.reason or "")
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    action = "fp_marked" if body.false_positive else "fp_cleared"
    add_audit_log(current_user["username"], action, "incident", incident_id, body.reason or "")
    return row
