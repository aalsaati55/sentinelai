"""
routers/live.py

POST /api/live/ingest   — agent sends raw log lines here
WS   /api/live/ws       — dashboard connects here for real-time events
"""

import json as _json
import logging
import time
import hashlib
from collections import defaultdict
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from typing import List, Dict

from ws_manager import manager
from parser_auth import parse_auth_line
from parser_syslog import parse_syslog_line
from aggregator import aggregate_events
from anomaly_scoring import score_sessions
from detection import run_detection
from risk_scoring import score_alert
from storage import (
    insert_events_bulk, insert_alert, insert_incident, is_rule_suppressed,
    add_to_watchlist, get_alerts, get_incidents, link_incident_events, get_connection,
    clear_watchlist_removed, escalate_incident_risk, add_user_notification,
)
from correlation import correlate_alerts
from emailer import send_incident_alert

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/live", tags=["live"])

# ── Line-level dedup ─────────────────────────────────────────────
# Collapses duplicate lines WITHIN a single batch only.
# This handles agents that send the same line 2-4x in one POST.
# We do NOT dedup across batches — that would swallow repeated logins
# (e.g. fakeuser1 connecting again later is a legitimate new event).
def _dedup_lines(lines: List[str]) -> List[str]:
    seen: set = set()
    unique = []
    for line in lines:
        h = hashlib.md5(line.encode(), usedforsecurity=False).hexdigest()
        if h not in seen:
            seen.add(h)
            unique.append(line)
    return unique

# ── Rolling per-IP failed login counter ───────────────────────
# Structure: { ip_user_key: {"count": int, "last_seen": float} }
_FAIL_WINDOW = 900  # seconds — match aggregation window
_fail_counter: Dict[str, dict] = defaultdict(lambda: {"count": 0, "last_seen": 0.0})

# ── Rolling per-IP invalid user counter (across different usernames) ───────────
# Key is source_ip only — accumulates fakeuser1, fakeuser2, fakeuser3 etc.
_invalid_user_counter: Dict[str, dict] = defaultdict(lambda: {"count": 0, "last_seen": 0.0})

# ── Rolling per-IP port scan counter ───────────────────────────────────────
# Accumulates distinct blocked ports per IP across batches so nmap scans
# (which arrive one UFW line at a time) build up to the detection threshold.
# Structure: { ip: {"ports": set(), "last_seen": float, "fired_severity": str|None} }
_port_scan_counter: Dict[str, dict] = {}

# ── Cross-batch behavioral flags ─────────────────────────────────────────────
# Tracks IPs that had ≥THRESHOLD failures so that a later success batch
# from the same IP can still fire success_after_failures / privilege_after_login.
# Structure: { ip: last_seen_ts }
_ip_had_failures: Dict[str, float] = {}   # ip -> timestamp of last failure batch

_PARSERS = {
    "auth":   parse_auth_line,
    "syslog": parse_syslog_line,
}


# ── Schemas ───────────────────────────────────────────────────

class LogBatch(BaseModel):
    source: str          # "auth" | "syslog"
    lines:  List[str]


# ── WebSocket — dashboard client ──────────────────────────────

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()   # keep-alive ping from client
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ── POST — agent sends log lines ──────────────────────────────

@router.post("/ingest")
async def ingest_lines(batch: LogBatch):
    """
    Receive a batch of raw log lines from the log agent running on the
    target VM. Parse, detect, score, store, and broadcast to dashboard.
    """
    if not batch.lines:
        return {"processed": 0, "events": 0, "alerts": 0}

    parser = _PARSERS.get(batch.source)
    if not parser:
        return {"error": f"Unknown source '{batch.source}'. Use 'auth' or 'syslog'"}

    # 1. Deduplicate lines — agent sometimes ships the same line 2-4x
    unique_lines = _dedup_lines(batch.lines)

    # 1. Parse lines into normalised events
    events = []
    for line in unique_lines:
        line = line.strip()
        if not line:
            continue
        try:
            event = parser(line)
            if event:
                events.append(event)
        except Exception as e:
            logger.warning(f"[live/{batch.source}] Parse error: {e}")

    if not events:
        return {"processed": len(batch.lines), "events": 0, "alerts": 0}

    # 2. Store events
    insert_events_bulk(events)

    # 3. Aggregate into sessions + score anomalies
    sessions = aggregate_events(events)
    if len(sessions) >= 2:
        score_sessions(sessions)
    else:
        for s in sessions:
            s.setdefault("anomaly_score", 0.0)
            s.setdefault("anomaly_level", "low")

    # Accumulate failed logins and invalid-user counts across batches within window
    now_ts = time.time()
    for s in sessions:
        ip  = s.get("source_ip") or "unknown"
        key = f"{ip}|{s.get('username','?')}"

        # Wrong-password failures (keyed per ip|user)
        entry = _fail_counter[key]
        if now_ts - entry["last_seen"] > _FAIL_WINDOW:
            entry["count"] = 0
        entry["count"]    += s.get("failed_login_count", 0)
        entry["last_seen"] = now_ts
        if entry["count"] > s.get("failed_login_count", 0):
            s["failed_login_count"] = entry["count"]

        # Invalid-user attempts (keyed per ip only — accumulates across different fake usernames)
        inv_entry = _invalid_user_counter[ip]
        if now_ts - inv_entry["last_seen"] > _FAIL_WINDOW:
            inv_entry["count"] = 0
        inv_entry["count"]    += s.get("invalid_user_count", 0)
        inv_entry["last_seen"] = now_ts
        # Inject accumulated IP-level total so invalid_user_enumeration rule fires correctly
        if inv_entry["count"] > s.get("ip_invalid_user_count", 0):
            s["ip_invalid_user_count"] = inv_entry["count"]

        # Port scan accumulation (keyed per ip only — UFW lines arrive one at a time)
        if ip not in _port_scan_counter:
            _port_scan_counter[ip] = {"ports": set(), "last_seen": 0.0, "fired_severity": None}
        ps_entry = _port_scan_counter[ip]
        # Reset if outside window
        if now_ts - ps_entry["last_seen"] > _FAIL_WINDOW:
            ps_entry["ports"] = set()
            ps_entry["fired_severity"] = None
        # Extract blocked ports from this session's PORT_SCAN events
        for e in s.get("events", []):
            if e.get("event_type") == "port_scan":
                msg = e.get("message", "")
                if "port " in msg:
                    port_str = msg.split("port ")[-1].split()[0].strip()
                    if port_str.isdigit():
                        ps_entry["ports"].add(port_str)
        ps_entry["last_seen"] = now_ts
        total_ports = len(ps_entry["ports"])
        # Determine what severity would fire at this count
        new_sev = None
        if total_ports >= 8:
            new_sev = "high"
        elif total_ports >= 3:
            new_sev = "medium"
        # Only inject if we haven't fired at this severity yet (prevents duplicate medium alerts)
        # and always inject if escalating from medium → high
        _sev_rank = {"medium": 1, "high": 2}
        prev_rank = _sev_rank.get(ps_entry["fired_severity"], 0)
        new_rank  = _sev_rank.get(new_sev, 0)
        if new_sev and new_rank > prev_rank:
            s["ip_unique_ports_scanned"] = total_ports
            ps_entry["fired_severity"] = new_sev
        elif new_sev and new_rank == prev_rank:
            # Already fired at this level — suppress by not injecting
            pass

        # Cross-batch success_after_failures:
        # If this IP had ≥ threshold failures in a prior batch within the window,
        # and this batch contains a successful login — set the flag.
        failed_total = _fail_counter[key]["count"]
        if failed_total >= 1:  # any prior failure from this ip|user
            _ip_had_failures[ip] = now_ts
        # Evict expired failure memory
        if ip in _ip_had_failures and now_ts - _ip_had_failures[ip] > _FAIL_WINDOW:
            del _ip_had_failures[ip]
        # Inject flags into session
        if ip in _ip_had_failures:
            s["ip_had_recent_failures"] = True
            # If this session also has a successful login → it's a success after failures
            if s.get("success_login_count", 0) > 0 and not s.get("success_after_failures"):
                s["success_after_failures"] = True
            # If this session also has sudo → privilege after login after brute force
            if s.get("sudo_count", 0) > 0 and not s.get("privilege_after_login"):
                s["privilege_after_login"] = True

    # 4. Run detection rules + score alerts (skip suppressed rules)
    alerts = run_detection(sessions)
    alerts = [a for a in alerts if not is_rule_suppressed(a.get("rule_name", ""))]
    for alert in alerts:
        score_alert(alert)
        insert_alert(alert)
        if alert.get("severity") in ("critical", "high"):
            send_incident_alert(alert)
        # Auto-watchlist source IP on Critical or High alerts
        if alert.get("severity") in ("critical", "high") and alert.get("source_ip"):
            clear_watchlist_removed(alert["source_ip"])
            add_to_watchlist(
                alert["source_ip"],
                reason=f"Auto-watchlisted: {alert.get('rule_name', 'unknown')} fired",
                added_by="system",
            )
            logger.info(f"[watchlist] Auto-added {alert['source_ip']} (rule: {alert.get('rule_name')})")

    # 5. Auto-correlate new alerts into incidents (per affected source IP)
    if alerts:
        affected_ips = {a.get("source_ip") for a in alerts if a.get("source_ip")}
        for ip in affected_ips:
            # Fetch all stored alerts for this IP
            with get_connection() as conn:
                rows = conn.execute(
                    "SELECT * FROM alerts WHERE source_ip = ? ORDER BY created_at ASC",
                    (ip,)
                ).fetchall()
            ip_alerts = []
            for r in rows:
                row = dict(r)
                raw = row.get("mitre_techniques")
                row["mitre_techniques"] = _json.loads(raw) if raw else []
                ip_alerts.append(row)

            # Dedup by IP + title — ignore username so fakeuser1/2/3 don't spawn separate incidents
            existing = get_incidents(limit=500)
            existing_keys = {
                (i.get("source_ip"), i["title"])
                for i in existing
            }

            new_incidents = correlate_alerts(ip_alerts)
            for inc in new_incidents:
                if (ip, inc["title"]) in existing_keys:
                    # ── Auto-escalation: bump risk score on existing open incident ──
                    existing_inc = next(
                        (i for i in existing if i.get("source_ip") == ip and i["title"] == inc["title"] and i["status"] != "closed"),
                        None
                    )
                    if existing_inc:
                        new_score = max(inc.get("risk_score", 0), existing_inc["risk_score"] + 5)
                        new_score = min(new_score, 100)
                        result = escalate_incident_risk(existing_inc["id"], new_score)
                        if result:
                            logger.info(f"[live] Escalated incident #{existing_inc['id']} risk {result['old_score']} → {result['new_score']}")
                            # Notify all users that the incident has escalated
                            with get_connection() as conn:
                                users = conn.execute("SELECT username FROM users").fetchall()
                            for u in users:
                                add_user_notification(
                                    username=u["username"],
                                    type_="escalation",
                                    title=f"Incident escalated: {existing_inc['title']}",
                                    body=f"Risk score raised {result['old_score']} → {result['new_score']} as new alerts arrived from {ip}",
                                    link_id=existing_inc["id"],
                                )
                            await manager.broadcast({
                                "type": "incident_escalated",
                                "data": {
                                    "incident_id": existing_inc["id"],
                                    "title":       existing_inc["title"],
                                    "old_score":   result["old_score"],
                                    "new_score":   result["new_score"],
                                    "source_ip":   ip,
                                }
                            })
                    continue
                inc_id = insert_incident(inc)
                # Link event IDs to the incident
                event_ids = [a["event_id"] for a in inc.get("alerts", []) if a.get("event_id")]
                if event_ids:
                    link_incident_events(inc_id, event_ids)
                logger.info(f"[live] Auto-created incident #{inc_id}: {inc['title']} (ip={ip})")

    # 6. Broadcast each new event to connected dashboard clients
    for event in events:
        await manager.broadcast({
            "type": "event",
            "data": {
                "timestamp":  event.get("timestamp"),
                "source":     event.get("source"),
                "event_type": event.get("event_type"),
                "source_ip":  event.get("source_ip"),
                "username":   event.get("username"),
                "message":    event.get("message", ""),
                "status":     event.get("status"),
            }
        })

    # 6. Broadcast each new alert
    for alert in alerts:
        await manager.broadcast({
            "type": "alert",
            "data": {
                "rule_name":     alert.get("rule_name"),
                "severity":      alert.get("severity"),
                "risk_score":    alert.get("risk_score"),
                "anomaly_level": alert.get("anomaly_level"),
                "source_ip":     alert.get("source_ip"),
                "username":      alert.get("username"),
                "description":   alert.get("description", ""),
            }
        })

    dupes = len(batch.lines) - len(unique_lines)
    logger.info(
        f"Live ingest [{batch.source}]: {len(batch.lines)} lines "
        f"({dupes} dupes dropped) → {len(events)} events, {len(alerts)} alerts broadcast."
    )
    return {"processed": len(batch.lines), "unique": len(unique_lines), "events": len(events), "alerts": len(alerts)}
