"""
storage.py

SQLite database layer.
Handles schema initialization and CRUD operations for:
    - events
    - alerts
    - incidents
    - incident_events
"""

import sqlite3
import logging
from typing import List, Dict, Any, Optional

from config import DATABASE_PATH
from utils import now_iso, ensure_dir
import os

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# Connection
# ──────────────────────────────────────────────

def get_connection() -> sqlite3.Connection:
    """Return a SQLite connection with row_factory set to dict-like rows."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


# ──────────────────────────────────────────────
# Schema
# ──────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    log_source  TEXT    NOT NULL,
    event_type  TEXT    NOT NULL,
    source_ip   TEXT,
    username    TEXT,
    hostname    TEXT,
    status      TEXT    NOT NULL,
    message     TEXT    NOT NULL,
    raw_log     TEXT    NOT NULL,
    created_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id       INTEGER REFERENCES events(id) ON DELETE SET NULL,
    rule_name      TEXT    NOT NULL,
    severity       TEXT    NOT NULL,
    risk_score        INTEGER NOT NULL DEFAULT 0,
    anomaly_score     REAL,
    anomaly_level     TEXT,
    description       TEXT    NOT NULL,
    mitre_techniques  TEXT,
    created_at        TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    title          TEXT    NOT NULL,
    description    TEXT    NOT NULL,
    source_ip      TEXT,
    username       TEXT,
    risk_score     INTEGER NOT NULL DEFAULT 0,
    anomaly_level  TEXT,
    status         TEXT    NOT NULL DEFAULT 'open',
    assigned_to    TEXT,
    created_at     TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS incident_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    event_id    INTEGER NOT NULL REFERENCES events(id)    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS incident_notes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    username    TEXT    NOT NULL,
    note        TEXT    NOT NULL,
    created_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT    NOT NULL,
    action      TEXT    NOT NULL,
    target_type TEXT    NOT NULL,
    target_id   INTEGER,
    detail      TEXT,
    created_at  TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp  ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_ip  ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_alerts_severity   ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_status  ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at);

CREATE TABLE IF NOT EXISTS watchlist (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip   TEXT    NOT NULL UNIQUE,
    reason      TEXT,
    added_by    TEXT    NOT NULL DEFAULT 'system',
    alert_count INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS suppressed_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name   TEXT    NOT NULL UNIQUE,
    suppressed_by TEXT  NOT NULL,
    reason      TEXT,
    created_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS watchlist_removed (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip   TEXT    NOT NULL UNIQUE,
    removed_by  TEXT    NOT NULL,
    removed_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS threat_intel_cache (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    ip               TEXT    NOT NULL UNIQUE,
    abuse_score      INTEGER NOT NULL DEFAULT 0,
    total_reports    INTEGER NOT NULL DEFAULT 0,
    country_code     TEXT,
    isp              TEXT,
    domain           TEXT,
    is_tor           INTEGER NOT NULL DEFAULT 0,
    categories       TEXT,
    last_reported_at TEXT,
    cached_at        TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS ssh_config (
    id         INTEGER PRIMARY KEY DEFAULT 1,
    host       TEXT    NOT NULL DEFAULT '',
    port       INTEGER NOT NULL DEFAULT 22,
    username   TEXT    NOT NULL DEFAULT '',
    key_path   TEXT    NOT NULL DEFAULT '',
    updated_at TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS user_notifications (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT    NOT NULL,
    type        TEXT    NOT NULL,
    title       TEXT    NOT NULL,
    body        TEXT    NOT NULL,
    link_id     INTEGER,
    read        INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_user_notifs_username ON user_notifications(username, created_at);
"""


def init_db() -> None:
    """
    Create all tables and indexes if they do not exist.
    Safe to call multiple times (uses IF NOT EXISTS).
    """
    ensure_dir(os.path.dirname(DATABASE_PATH))
    with get_connection() as conn:
        conn.executescript(_SCHEMA)
        # Migrations: add columns that may not exist in older DBs
        for sql in [
            "ALTER TABLE incidents ADD COLUMN assigned_to TEXT",
            "ALTER TABLE alerts ADD COLUMN mitre_techniques TEXT",
            "ALTER TABLE alerts ADD COLUMN source_ip TEXT",
            "ALTER TABLE alerts ADD COLUMN username TEXT",
            "ALTER TABLE watchlist ADD COLUMN alert_count INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE threat_intel_cache ADD COLUMN is_tor INTEGER NOT NULL DEFAULT 0",
        ]:
            try:
                conn.execute(sql)
            except Exception:
                pass  # Column already exists
    logger.info("Database initialized.")


# ──────────────────────────────────────────────
# Suppressed Rules
# ──────────────────────────────────────────────

def get_suppressed_rules() -> List[Dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM suppressed_rules ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]


def is_rule_suppressed(rule_name: str) -> bool:
    with get_connection() as conn:
        row = conn.execute("SELECT id FROM suppressed_rules WHERE rule_name = ?", (rule_name,)).fetchone()
    return row is not None


def suppress_rule(rule_name: str, suppressed_by: str, reason: str = "") -> Dict[str, Any]:
    with get_connection() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO suppressed_rules (rule_name, suppressed_by, reason, created_at) VALUES (?, ?, ?, ?)",
            (rule_name, suppressed_by, reason, now_iso()),
        )
        row = conn.execute("SELECT * FROM suppressed_rules WHERE rule_name = ?", (rule_name,)).fetchone()
    return dict(row)


def unsuppress_rule(rule_name: str) -> bool:
    with get_connection() as conn:
        cur = conn.execute("DELETE FROM suppressed_rules WHERE rule_name = ?", (rule_name,))
    return cur.rowcount > 0


# ──────────────────────────────────────────────
# Watchlist
# ──────────────────────────────────────────────

def get_watchlist() -> List[Dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM watchlist ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]


def get_watchlisted_ips() -> set:
    """Return set of all watchlisted IPs for fast O(1) lookups."""
    with get_connection() as conn:
        rows = conn.execute("SELECT source_ip FROM watchlist").fetchall()
    return {r["source_ip"] for r in rows}


def is_ip_watchlisted(ip: str) -> bool:
    with get_connection() as conn:
        row = conn.execute("SELECT id FROM watchlist WHERE source_ip = ?", (ip,)).fetchone()
    return row is not None


def add_to_watchlist(ip: str, reason: str = "", added_by: str = "system") -> Dict[str, Any]:
    """Add IP to watchlist or increment its alert_count if already listed."""
    with get_connection() as conn:
        existing = conn.execute("SELECT * FROM watchlist WHERE source_ip = ?", (ip,)).fetchone()
        if existing:
            conn.execute(
                "UPDATE watchlist SET alert_count = alert_count + 1, reason = ? WHERE source_ip = ?",
                (reason or dict(existing)["reason"], ip),
            )
        else:
            conn.execute(
                "INSERT INTO watchlist (source_ip, reason, added_by, alert_count, created_at) VALUES (?, ?, ?, 1, ?)",
                (ip, reason, added_by, now_iso()),
            )
        row = conn.execute("SELECT * FROM watchlist WHERE source_ip = ?", (ip,)).fetchone()
    return dict(row)


def remove_from_watchlist(ip: str, removed_by: str = "admin") -> bool:
    with get_connection() as conn:
        cur = conn.execute("DELETE FROM watchlist WHERE source_ip = ?", (ip,))
        if cur.rowcount > 0:
            conn.execute(
                "INSERT OR REPLACE INTO watchlist_removed (source_ip, removed_by, removed_at) VALUES (?, ?, ?)",
                (ip, removed_by, now_iso()),
            )
    return cur.rowcount > 0


def was_watchlist_manually_removed(ip: str) -> bool:
    """Returns True if this IP was previously manually removed from watchlist."""
    with get_connection() as conn:
        row = conn.execute("SELECT id FROM watchlist_removed WHERE source_ip = ?", (ip,)).fetchone()
    return row is not None


def clear_watchlist_removed(ip: str) -> None:
    """Clear the manual-removal record so auto-watchlist can re-add it."""
    with get_connection() as conn:
        conn.execute("DELETE FROM watchlist_removed WHERE source_ip = ?", (ip,))


# ──────────────────────────────────────────────
# Notification helpers
# ──────────────────────────────────────────────

def get_recent_critical_alerts(since_iso: str, limit: int = 20) -> List[Dict[str, Any]]:
    """Fetch critical/high alerts created after since_iso for the notification bell."""
    import json as _json
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE severity IN ('critical','high') AND created_at > ? ORDER BY created_at DESC LIMIT ?",
            (since_iso, limit),
        ).fetchall()
    results = []
    for r in rows:
        row = dict(r)
        raw = row.get("mitre_techniques")
        row["mitre_techniques"] = _json.loads(raw) if raw else []
        results.append(row)
    return results


# ──────────────────────────────────────────────
# Events
# ──────────────────────────────────────────────

def insert_event(event: Dict[str, Any]) -> int:
    """
    Insert a normalized event dict into the events table.
    Returns the new row id.
    """
    sql = """
        INSERT INTO events
            (timestamp, log_source, event_type, source_ip, username,
             hostname, status, message, raw_log, created_at)
        VALUES
            (:timestamp, :log_source, :event_type, :source_ip, :username,
             :hostname, :status, :message, :raw_log, :created_at)
    """
    row = {**event, "created_at": now_iso()}
    with get_connection() as conn:
        cursor = conn.execute(sql, row)
        return cursor.lastrowid


def insert_events_bulk(events: List[Dict[str, Any]]) -> int:
    """
    Insert multiple events in a single transaction.
    Returns the number of rows inserted.
    """
    if not events:
        return 0
    sql = """
        INSERT INTO events
            (timestamp, log_source, event_type, source_ip, username,
             hostname, status, message, raw_log, created_at)
        VALUES
            (:timestamp, :log_source, :event_type, :source_ip, :username,
             :hostname, :status, :message, :raw_log, :created_at)
    """
    rows = [{**e, "created_at": now_iso()} for e in events]
    with get_connection() as conn:
        conn.executemany(sql, rows)
    logger.info(f"Inserted {len(rows)} events.")
    return len(rows)


def get_events(
    limit: int = 500,
    offset: int = 0,
    event_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    log_source: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Fetch events with optional filters. Returns list of dicts."""
    conditions = []
    params: Dict[str, Any] = {"limit": limit, "offset": offset}

    if event_type:
        conditions.append("event_type = :event_type")
        params["event_type"] = event_type
    if source_ip:
        conditions.append("source_ip = :source_ip")
        params["source_ip"] = source_ip
    if log_source:
        conditions.append("log_source = :log_source")
        params["log_source"] = log_source

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    sql = f"SELECT * FROM events {where} ORDER BY timestamp DESC LIMIT :limit OFFSET :offset"

    with get_connection() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def count_events() -> int:
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]


# ──────────────────────────────────────────────
# Alerts
# ──────────────────────────────────────────────

def insert_alert(alert: Dict[str, Any]) -> int:
    """
    Insert an alert dict into the alerts table.
    Returns the new row id.
    """
    import json as _json
    sql = """
        INSERT INTO alerts
            (event_id, rule_name, severity, risk_score,
             anomaly_score, anomaly_level, description, mitre_techniques,
             source_ip, username, created_at)
        VALUES
            (:event_id, :rule_name, :severity, :risk_score,
             :anomaly_score, :anomaly_level, :description, :mitre_techniques,
             :source_ip, :username, :created_at)
    """
    techniques = alert.get("mitre_techniques", [])
    row = {
        "event_id":         alert.get("event_id"),
        "rule_name":        alert["rule_name"],
        "severity":         alert["severity"],
        "risk_score":       alert.get("risk_score", 0),
        "anomaly_score":    alert.get("anomaly_score"),
        "anomaly_level":    alert.get("anomaly_level"),
        "description":      alert["description"],
        "mitre_techniques": _json.dumps(techniques) if techniques else None,
        "source_ip":        alert.get("source_ip"),
        "username":         alert.get("username"),
        "created_at":       now_iso(),
    }
    with get_connection() as conn:
        cursor = conn.execute(sql, row)
        return cursor.lastrowid


def get_alerts(
    limit: int = 200,
    offset: int = 0,
    severity: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Fetch alerts with optional severity filter."""
    import json as _json
    params: Dict[str, Any] = {"limit": limit, "offset": offset}
    where = ""
    if severity:
        where = "WHERE severity = :severity"
        params["severity"] = severity

    sql = f"SELECT * FROM alerts {where} ORDER BY created_at DESC LIMIT :limit OFFSET :offset"
    with get_connection() as conn:
        rows = conn.execute(sql, params).fetchall()
    results = []
    for r in rows:
        row = dict(r)
        raw = row.get("mitre_techniques")
        row["mitre_techniques"] = _json.loads(raw) if raw else []
        results.append(row)
    return results


def count_alerts(severity: Optional[str] = None) -> int:
    if severity:
        with get_connection() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE severity = ?", (severity,)
            ).fetchone()[0]
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]


# ──────────────────────────────────────────────
# Incidents
# ──────────────────────────────────────────────

def insert_incident(incident: Dict[str, Any]) -> int:
    """
    Insert an incident dict into the incidents table.
    Returns the new row id.
    """
    sql = """
        INSERT INTO incidents
            (title, description, source_ip, username,
             risk_score, anomaly_level, status, created_at)
        VALUES
            (:title, :description, :source_ip, :username,
             :risk_score, :anomaly_level, :status, :created_at)
    """
    row = {
        "title":         incident["title"],
        "description":   incident["description"],
        "source_ip":     incident.get("source_ip"),
        "username":      incident.get("username"),
        "risk_score":    incident.get("risk_score", 0),
        "anomaly_level": incident.get("anomaly_level"),
        "status":        incident.get("status", "open"),
        "created_at":    now_iso(),
    }
    with get_connection() as conn:
        cursor = conn.execute(sql, row)
        return cursor.lastrowid


def link_incident_events(incident_id: int, event_ids: List[int]) -> None:
    """Link a list of event IDs to an incident in incident_events."""
    if not event_ids:
        return
    sql = "INSERT INTO incident_events (incident_id, event_id) VALUES (?, ?)"
    rows = [(incident_id, eid) for eid in event_ids]
    with get_connection() as conn:
        conn.executemany(sql, rows)


def get_incidents(
    limit: int = 100,
    offset: int = 0,
    status: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Fetch incidents with optional status filter."""
    params: Dict[str, Any] = {"limit": limit, "offset": offset}
    where = ""
    if status:
        where = "WHERE status = :status"
        params["status"] = status

    sql = f"""
        SELECT i.*,
               (SELECT COUNT(*) FROM incident_notes n WHERE n.incident_id = i.id) AS note_count
        FROM incidents i {where}
        ORDER BY i.created_at DESC
        LIMIT :limit OFFSET :offset
    """
    with get_connection() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def get_incident_events(incident_id: int) -> List[Dict[str, Any]]:
    """Fetch all events linked to a given incident."""
    sql = """
        SELECT e.*
        FROM events e
        JOIN incident_events ie ON ie.event_id = e.id
        WHERE ie.incident_id = ?
        ORDER BY e.timestamp ASC
    """
    with get_connection() as conn:
        rows = conn.execute(sql, (incident_id,)).fetchall()
    return [dict(r) for r in rows]


def count_incidents(status: Optional[str] = None) -> int:
    if status:
        with get_connection() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM incidents WHERE status = ?", (status,)
            ).fetchone()[0]
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]


# ──────────────────────────────────────────────
# Dashboard helpers
# ──────────────────────────────────────────────

def get_top_source_ips(limit: int = 10) -> List[Dict[str, Any]]:
    """Return top source IPs by event count."""
    sql = """
        SELECT source_ip, COUNT(*) as count
        FROM events
        WHERE source_ip IS NOT NULL
        GROUP BY source_ip
        ORDER BY count DESC
        LIMIT ?
    """
    with get_connection() as conn:
        rows = conn.execute(sql, (limit,)).fetchall()
    return [dict(r) for r in rows]


def get_event_type_distribution() -> List[Dict[str, Any]]:
    """Return event counts grouped by event_type."""
    sql = """
        SELECT event_type, COUNT(*) as count
        FROM events
        GROUP BY event_type
        ORDER BY count DESC
    """
    with get_connection() as conn:
        rows = conn.execute(sql).fetchall()
    return [dict(r) for r in rows]


def get_severity_breakdown() -> List[Dict[str, Any]]:
    """Return alert counts grouped by severity."""
    sql = """
        SELECT severity, COUNT(*) as count
        FROM alerts
        GROUP BY severity
        ORDER BY count DESC
    """
    with get_connection() as conn:
        rows = conn.execute(sql).fetchall()
    return [dict(r) for r in rows]


def get_event_timeline(bucket: str = "hour") -> List[Dict[str, Any]]:
    """
    Return event counts bucketed by time.
    bucket: 'hour' or 'day'
    """
    fmt = "%Y-%m-%dT%H:00:00" if bucket == "hour" else "%Y-%m-%d"
    sql = f"""
        SELECT strftime('{fmt}', timestamp) as period, COUNT(*) as count
        FROM events
        GROUP BY period
        ORDER BY period ASC
    """
    with get_connection() as conn:
        rows = conn.execute(sql).fetchall()
    return [dict(r) for r in rows]


def get_incident_timeline(days: int = 30) -> List[Dict[str, Any]]:
    """Return incident counts per day for the last N days."""
    sql = """
        SELECT strftime('%Y-%m-%d', created_at) as day, COUNT(*) as count
        FROM incidents
        WHERE created_at >= datetime('now', ?)
        GROUP BY day
        ORDER BY day ASC
    """
    with get_connection() as conn:
        rows = conn.execute(sql, (f"-{days} days",)).fetchall()
    return [dict(r) for r in rows]


def get_alert_timeline(days: int = 30) -> List[Dict[str, Any]]:
    """Return alert counts per day per severity for the last N days."""
    sql = """
        SELECT strftime('%Y-%m-%d', created_at) as day, severity, COUNT(*) as count
        FROM alerts
        WHERE created_at >= datetime('now', ?)
        GROUP BY day, severity
        ORDER BY day ASC
    """
    with get_connection() as conn:
        rows = conn.execute(sql, (f"-{days} days",)).fetchall()
    return [dict(r) for r in rows]


def get_unique_ip_count() -> int:
    with get_connection() as conn:
        return conn.execute(
            "SELECT COUNT(DISTINCT source_ip) FROM events WHERE source_ip IS NOT NULL"
        ).fetchone()[0]


def add_audit_log(username: str, action: str, target_type: str, target_id: int = None, detail: str = None) -> None:
    """Record an audit log entry."""
    from utils import now_iso
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO audit_log (username, action, target_type, target_id, detail, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (username, action, target_type, target_id, detail, now_iso()),
        )


def get_audit_log(limit: int = 200, offset: int = 0) -> List[Dict[str, Any]]:
    """Return audit log entries newest-first."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    return [dict(r) for r in rows]


def add_incident_note(incident_id: int, username: str, note: str) -> dict:
    sql = """
        INSERT INTO incident_notes (incident_id, username, note, created_at)
        VALUES (?, ?, ?, ?)
    """
    from utils import now_iso
    with get_connection() as conn:
        cursor = conn.execute(sql, (incident_id, username, note, now_iso()))
        row_id = cursor.lastrowid
        row = conn.execute("SELECT * FROM incident_notes WHERE id = ?", (row_id,)).fetchone()
    return dict(row)


def get_incident_notes(incident_id: int) -> List[Dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM incident_notes WHERE incident_id = ? ORDER BY created_at ASC",
            (incident_id,)
        ).fetchall()
    return [dict(r) for r in rows]


# ──────────────────────────────────────────────
# SSH Config
# ──────────────────────────────────────────────

def get_ssh_config() -> Dict[str, Any]:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM ssh_config WHERE id = 1").fetchone()
    if row:
        return dict(row)
    return {"id": 1, "host": "", "port": 22, "username": "", "key_path": "", "updated_at": ""}


def save_ssh_config(host: str, port: int, username: str, key_path: str) -> Dict[str, Any]:
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO ssh_config (id, host, port, username, key_path, updated_at)
               VALUES (1, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                   host=excluded.host, port=excluded.port,
                   username=excluded.username, key_path=excluded.key_path,
                   updated_at=excluded.updated_at""",
            (host, port, username, key_path, now_iso()),
        )
    return get_ssh_config()


# ──────────────────────────────────────────────
# User Notifications
# ──────────────────────────────────────────────

def add_user_notification(username: str, type_: str, title: str, body: str, link_id: int = None) -> Dict[str, Any]:
    """Create an in-app notification for a specific user."""
    with get_connection() as conn:
        cursor = conn.execute(
            "INSERT INTO user_notifications (username, type, title, body, link_id, read, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)",
            (username, type_, title, body, link_id, now_iso()),
        )
        row = conn.execute("SELECT * FROM user_notifications WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return dict(row)


def get_user_notifications(username: str, since_iso: str = None, limit: int = 30) -> List[Dict[str, Any]]:
    """Fetch unread notifications for a user, optionally filtered by since_iso."""
    if since_iso:
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM user_notifications WHERE username = ? AND created_at > ? ORDER BY created_at DESC LIMIT ?",
                (username, since_iso, limit),
            ).fetchall()
    else:
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM user_notifications WHERE username = ? ORDER BY created_at DESC LIMIT ?",
                (username, limit),
            ).fetchall()
    return [dict(r) for r in rows]


def mark_user_notifications_read(username: str) -> None:
    with get_connection() as conn:
        conn.execute("UPDATE user_notifications SET read = 1 WHERE username = ?", (username,))


def clear_user_notifications(username: str) -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM user_notifications WHERE username = ?", (username,))


def clear_all_data() -> None:
    """Delete all rows from all tables. Used for testing/reset only."""
    with get_connection() as conn:
        conn.executescript("""
            DELETE FROM incident_events;
            DELETE FROM incidents;
            DELETE FROM alerts;
            DELETE FROM events;
        """)
    logger.warning("All data cleared from database.")
