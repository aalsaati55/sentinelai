"""
routers/live.py

POST /api/live/ingest   — agent sends raw log lines here
WS   /api/live/ws       — dashboard connects here for real-time events
"""

import logging
import time
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
from storage import insert_events_bulk, insert_alert, insert_incident, is_rule_suppressed
from emailer import send_incident_alert

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/live", tags=["live"])

# Rolling per-IP failed login counter — accumulates across batches within 5 min
# Structure: { ip_user_key: {"count": int, "last_seen": float} }
_FAIL_WINDOW = 300  # seconds
_fail_counter: Dict[str, dict] = defaultdict(lambda: {"count": 0, "last_seen": 0.0})

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

    # 1. Parse lines into normalised events
    events = []
    for line in batch.lines:
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

    # Accumulate failed logins across batches per IP|user within 5-min window
    now_ts = time.time()
    for s in sessions:
        key = f"{s.get('source_ip','?')}|{s.get('username','?')}"
        entry = _fail_counter[key]
        # Reset if outside window
        if now_ts - entry["last_seen"] > _FAIL_WINDOW:
            entry["count"] = 0
        entry["count"]     += s.get("failed_login_count", 0)
        entry["last_seen"]  = now_ts
        # Inject accumulated count back so detection sees the full picture
        if entry["count"] > s.get("failed_login_count", 0):
            s["failed_login_count"] = entry["count"]

    # 4. Run detection rules + score alerts (skip suppressed rules)
    alerts = run_detection(sessions)
    alerts = [a for a in alerts if not is_rule_suppressed(a.get("rule_name", ""))]
    for alert in alerts:
        score_alert(alert)
        insert_alert(alert)
        if alert.get("severity") in ("critical", "high"):
            send_incident_alert(alert)

    # 5. Broadcast each new event to connected dashboard clients
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

    logger.info(
        f"Live ingest [{batch.source}]: {len(batch.lines)} lines → "
        f"{len(events)} events, {len(alerts)} alerts broadcast."
    )
    return {"processed": len(batch.lines), "events": len(events), "alerts": len(alerts)}
