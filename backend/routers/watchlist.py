"""
routers/watchlist.py

GET    /api/watchlist              — list all watchlisted IPs
POST   /api/watchlist              — manually add an IP (admin only)
DELETE /api/watchlist/{ip}         — remove an IP (admin only)
GET    /api/watchlist/check/{ip}   — check if an IP is watchlisted
GET    /api/incidents/{id}/playbook — response playbook for an incident
"""

import logging
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional

from storage import (
    get_watchlist, add_to_watchlist, remove_from_watchlist,
    is_ip_watchlisted, get_incident_events, get_connection,
    add_audit_log,
)
from auth import get_current_user
from utils import now_iso

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/watchlist", tags=["watchlist"])


# ── Playbook rules — maps alert rule names to response steps ────────────────
_PLAYBOOK: dict = {
    "reverse_shell_cron": [
        {"step": "Isolate the affected host immediately from the network",       "category": "contain"},
        {"step": "Inspect /etc/cron.d and /etc/crontab for malicious entries",   "category": "investigate"},
        {"step": "Kill any active reverse shell connections (check `ss -tnp`)",   "category": "contain"},
        {"step": "Run `sudo crontab -l` for all users to find hidden cron jobs",  "category": "investigate"},
        {"step": "Block the attacker IP at the firewall (ufw deny from <IP>)",    "category": "block"},
        {"step": "Rotate SSH keys and change all credentials on the host",        "category": "remediate"},
        {"step": "Review other hosts for lateral movement signs",                 "category": "investigate"},
    ],
    "success_after_failures": [
        {"step": "Verify the login was authorized with the account owner",        "category": "investigate"},
        {"step": "Check what commands were run after login (`last`, `history`)",  "category": "investigate"},
        {"step": "Block the source IP if login was unauthorized",                 "category": "block"},
        {"step": "Reset the compromised account password immediately",            "category": "remediate"},
        {"step": "Enable 2FA or SSH key-only authentication",                     "category": "remediate"},
    ],
    "brute_force_ssh": [
        {"step": "Block the source IP at the firewall",                           "category": "block"},
        {"step": "Check if any login succeeded from this IP in recent alerts",    "category": "investigate"},
        {"step": "Review /var/log/auth.log for full attack timeline",             "category": "investigate"},
        {"step": "Consider changing the SSH port or enabling Fail2Ban",           "category": "remediate"},
    ],
    "privilege_after_login": [
        {"step": "Verify the sudo command executed was authorized",               "category": "investigate"},
        {"step": "Check `sudo -l` audit logs for the user",                       "category": "investigate"},
        {"step": "Review what files/services were modified via sudo",             "category": "investigate"},
        {"step": "Revoke sudo access if privilege escalation was unauthorized",   "category": "remediate"},
    ],
    "sudo_after_suspicious_login": [
        {"step": "Confirm whether the sudo command was legitimate",               "category": "investigate"},
        {"step": "Check if attacker has persisted (new cron, user, SSH key)",     "category": "investigate"},
        {"step": "Block the source IP and reset credentials",                     "category": "block"},
        {"step": "Audit all changes made during the session",                     "category": "investigate"},
    ],
    "new_user_created": [
        {"step": "Check if the new user account was authorized",                  "category": "investigate"},
        {"step": "Disable or remove the account if unauthorized (`userdel`)",     "category": "remediate"},
        {"step": "Check if the account was added to sudoers",                     "category": "investigate"},
        {"step": "Audit who created the account and when",                        "category": "investigate"},
    ],
    "cron_modification": [
        {"step": "Review all crontabs: `crontab -l`, /etc/cron.d/, /etc/crontab","category": "investigate"},
        {"step": "Look for commands that call external IPs or download files",    "category": "investigate"},
        {"step": "Remove any unauthorized cron entries",                          "category": "remediate"},
        {"step": "Check for reverse shell indicators in cron commands",           "category": "investigate"},
    ],
    "port_scan_detected": [
        {"step": "Block the scanning IP at the firewall",                         "category": "block"},
        {"step": "Check which ports were probed and which are actually open",     "category": "investigate"},
        {"step": "Ensure only necessary ports are exposed (ufw status)",          "category": "remediate"},
        {"step": "Monitor for follow-up exploitation attempts from this IP",      "category": "monitor"},
    ],
    "invalid_user_enumeration": [
        {"step": "Block the source IP at the firewall",                           "category": "block"},
        {"step": "Check if any valid usernames were discovered (later brute force)","category": "monitor"},
        {"step": "Review all valid usernames and enforce strong passwords",       "category": "remediate"},
    ],
    "repeated_sudo_failures": [
        {"step": "Verify whether the failures were caused by a legitimate user",  "category": "investigate"},
        {"step": "Lock the account temporarily if abuse is suspected (`passwd -l`)","category": "contain"},
        {"step": "Check for password spraying against multiple accounts",         "category": "investigate"},
    ],
}

_DEFAULT_STEPS = [
    {"step": "Review the full alert timeline for this incident",                  "category": "investigate"},
    {"step": "Block the source IP if behaviour is confirmed malicious",           "category": "block"},
    {"step": "Escalate to senior analyst if impact is unclear",                   "category": "escalate"},
]

_CATEGORY_LABELS = {
    "contain":     {"label": "Contain",     "color": "red"},
    "block":       {"label": "Block",       "color": "orange"},
    "investigate": {"label": "Investigate", "color": "blue"},
    "remediate":   {"label": "Remediate",   "color": "purple"},
    "monitor":     {"label": "Monitor",     "color": "yellow"},
    "escalate":    {"label": "Escalate",    "color": "slate"},
}


class WatchlistAdd(BaseModel):
    source_ip: str
    reason: Optional[str] = ""


@router.get("")
def list_watchlist(current_user: dict = Depends(get_current_user)):
    return get_watchlist()


@router.post("", status_code=201)
def add_watchlist_entry(body: WatchlistAdd, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    entry = add_to_watchlist(body.source_ip, body.reason or "", added_by=current_user["username"])
    add_audit_log(
        username=current_user["username"],
        action="Watchlist Add",
        target_type="ip",
        detail=f"Added {body.source_ip} to watchlist — {body.reason or 'no reason given'}",
    )
    return entry


@router.delete("/{source_ip}")
def remove_watchlist_entry(source_ip: str, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    removed = remove_from_watchlist(source_ip)
    if not removed:
        raise HTTPException(status_code=404, detail="IP not in watchlist")
    add_audit_log(
        username=current_user["username"],
        action="Watchlist Remove",
        target_type="ip",
        detail=f"Removed {source_ip} from watchlist",
    )
    return {"removed": source_ip}


@router.get("/check/{source_ip}")
def check_watchlist(source_ip: str, current_user: dict = Depends(get_current_user)):
    return {"watchlisted": is_ip_watchlisted(source_ip)}


# ── Playbook — separate prefix ───────────────────────────────────────────────
playbook_router = APIRouter(prefix="/api/incidents", tags=["playbook"])


@playbook_router.get("/{incident_id}/playbook")
def get_playbook(incident_id: int, current_user: dict = Depends(get_current_user)):
    """
    Return a response playbook for an incident based on which alert rules fired.
    Steps are de-duplicated and ordered: contain → block → investigate → remediate → monitor.
    """
    with get_connection() as conn:
        exists = conn.execute("SELECT id FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if not exists:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Map incident title → rule name directly (most reliable approach)
    _TITLE_TO_RULE = {
        "brute force attack":               "brute_force_ssh",
        "possible credential compromise":   "success_after_failures",
        "ssh compromise":                   "success_after_failures",
        "full system compromise":           "reverse_shell_cron",
        "brute force ssh":                  "brute_force_ssh",
        "invalid user enumeration":         "invalid_user_enumeration",
        "port scan detected":               "port_scan_detected",
        "success after failures":           "success_after_failures",
        "reverse shell cron":               "reverse_shell_cron",
        "new user created":                 "new_user_created",
        "cron modification":                "cron_modification",
        "privilege after login":            "privilege_after_login",
        "sudo after suspicious login":      "sudo_after_suspicious_login",
        "repeated sudo failures":           "repeated_sudo_failures",
        "sensitive file":                   "sensitive_file_access",
        "system":                           "system_service_anomaly",
        "ssh login success":                "ssh_login_success",
        "suspicious login time":            "suspicious_login_time",
    }

    with get_connection() as conn:
        inc_row = conn.execute("SELECT title FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    title_lower = (inc_row["title"] if inc_row else "").lower()

    # Match title to rule(s)
    rules = []
    for keyword, rule in _TITLE_TO_RULE.items():
        if keyword in title_lower and rule not in rules:
            rules.append(rule)

    # If no title match, fall back to linked alert rules
    if not rules:
        with get_connection() as conn:
            alert_rows = conn.execute(
                """
                SELECT DISTINCT a.rule_name FROM alerts a
                JOIN incident_events ie ON ie.event_id = a.event_id
                WHERE ie.incident_id = ?
                ORDER BY a.created_at DESC LIMIT 20
                """,
                (incident_id,),
            ).fetchall()
        rules = [r["rule_name"] for r in alert_rows]

    # Gather steps, de-duplicate by step text
    seen = set()
    steps = []
    for rule in rules:
        for s in _PLAYBOOK.get(rule, []):
            if s["step"] not in seen:
                seen.add(s["step"])
                steps.append({**s, "done": False, "rule": rule})

    if not steps:
        for s in _DEFAULT_STEPS:
            steps.append({**s, "done": False, "rule": "general"})

    # Sort by category priority
    _ORDER = {"contain": 0, "block": 1, "investigate": 2, "remediate": 3, "monitor": 4, "escalate": 5}
    steps.sort(key=lambda s: _ORDER.get(s["category"], 99))

    # Attach category metadata
    for s in steps:
        s["category_meta"] = _CATEGORY_LABELS.get(s["category"], {"label": s["category"].title(), "color": "slate"})

    return {"incident_id": incident_id, "rules_triggered": rules, "steps": steps}
