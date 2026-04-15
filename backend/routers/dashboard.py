"""
routers/dashboard.py

GET /api/dashboard/summary    — top-level counts for the SOC overview panel
GET /api/dashboard/timeline   — event counts bucketed by hour or day
GET /api/dashboard/top-ips    — top source IPs by event volume
GET /api/dashboard/event-types — event type distribution
GET /api/dashboard/severity   — alert severity breakdown
"""

from fastapi import APIRouter, Query
from typing import List

from storage import (
    count_events, count_alerts, count_incidents,
    get_unique_ip_count,
    get_event_timeline,
    get_top_source_ips,
    get_event_type_distribution,
    get_severity_breakdown,
    get_incident_timeline,
    get_alert_timeline,
    get_connection,
)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/summary")
def summary():
    return {
        "total_events":        count_events(),
        "total_alerts":        count_alerts(),
        "open_incidents":      count_incidents(status="open"),
        "critical_alerts":     count_alerts(severity="critical"),
        "high_alerts":         count_alerts(severity="high"),
        "medium_alerts":       count_alerts(severity="medium"),
        "low_alerts":          count_alerts(severity="low"),
        "unique_source_ips":   get_unique_ip_count(),
    }


@router.get("/timeline")
def timeline(bucket: str = Query("hour", pattern="^(hour|day)$")):
    return get_event_timeline(bucket=bucket)


@router.get("/top-ips")
def top_ips(limit: int = Query(10, ge=1, le=50)):
    return get_top_source_ips(limit=limit)


@router.get("/event-types")
def event_types():
    return get_event_type_distribution()


@router.get("/severity")
def severity_breakdown():
    return get_severity_breakdown()


@router.get("/incident-timeline")
def incident_timeline(days: int = Query(30, ge=1, le=365)):
    return get_incident_timeline(days=days)


@router.get("/alert-timeline")
def alert_timeline(days: int = Query(30, ge=1, le=365)):
    return get_alert_timeline(days=days)


@router.get("/team-activity")
def team_activity():
    """Return per-analyst activity metrics: incidents closed, notes added, assignments, avg resolution time."""
    with get_connection() as conn:
        # Notes added per analyst
        notes_rows = conn.execute("""
            SELECT username, COUNT(*) as notes_added
            FROM incident_notes
            GROUP BY username
        """).fetchall()

        # Incidents closed per analyst (from audit log status_change → closed)
        closed_rows = conn.execute("""
            SELECT username, COUNT(*) as incidents_closed
            FROM audit_log
            WHERE action = 'status_change' AND detail LIKE '%closed%'
            GROUP BY username
        """).fetchall()

        # Incidents assigned per analyst
        assigned_rows = conn.execute("""
            SELECT assigned_to as username, COUNT(*) as incidents_assigned
            FROM incidents
            WHERE assigned_to IS NOT NULL AND assigned_to != ''
            GROUP BY assigned_to
        """).fetchall()

        # Avg resolution time per analyst (minutes) from audit log
        resolution_rows = conn.execute("""
            SELECT al.username,
                   ROUND(AVG(
                       (JULIANDAY(al.created_at) - JULIANDAY(i.created_at)) * 1440
                   ), 1) as avg_resolution_minutes
            FROM audit_log al
            JOIN incidents i ON i.id = al.target_id
            WHERE al.action = 'status_change' AND al.detail LIKE '%closed%'
            GROUP BY al.username
        """).fetchall()

        # SOAR commands executed per analyst
        soar_rows = conn.execute("""
            SELECT username, COUNT(*) as soar_executed
            FROM audit_log
            WHERE action = 'soar_executed'
            GROUP BY username
        """).fetchall()

    # Seed from live users table — deleted users will never appear
    with get_connection() as conn:
        live_users = conn.execute("SELECT username FROM users").fetchall()

    analysts = {
        row["username"]: {
            "username": row["username"],
            "incidents_closed": 0,
            "incidents_assigned": 0,
            "notes_added": 0,
            "soar_executed": 0,
            "avg_resolution_minutes": None,
        }
        for row in live_users
    }

    def _get(u):
        return analysts.get(u)  # returns None for deleted users — they are skipped

    for r in notes_rows:
        e = _get(r["username"])
        if e: e["notes_added"] = r["notes_added"]
    for r in closed_rows:
        e = _get(r["username"])
        if e: e["incidents_closed"] = r["incidents_closed"]
    for r in assigned_rows:
        e = _get(r["username"])
        if e: e["incidents_assigned"] = r["incidents_assigned"]
    for r in resolution_rows:
        e = _get(r["username"])
        if e: e["avg_resolution_minutes"] = r["avg_resolution_minutes"]
    for r in soar_rows:
        e = _get(r["username"])
        if e: e["soar_executed"] = r["soar_executed"]

    # Sort by incidents closed desc
    result = sorted(analysts.values(), key=lambda a: a["incidents_closed"], reverse=True)
    return result


@router.get("/mttd-mttr")
def mttd_mttr():
    """Return Mean Time to Detect and Mean Time to Respond in minutes."""
    import datetime
    with get_connection() as conn:
        # MTTD: avg minutes between first alert for an IP and incident creation
        mttd_row = conn.execute("""
            SELECT ROUND(AVG(
                (JULIANDAY(i.created_at) - JULIANDAY(a.first_alert)) * 1440
            ), 1) as mttd_minutes
            FROM incidents i
            JOIN (
                SELECT source_ip, MIN(created_at) as first_alert
                FROM alerts
                GROUP BY source_ip
            ) a ON a.source_ip = i.source_ip
            WHERE i.source_ip IS NOT NULL
        """).fetchone()

        # MTTR: avg minutes between incident creation and close (status=closed)
        mttr_row = conn.execute("""
            SELECT ROUND(AVG(
                (JULIANDAY(al.created_at) - JULIANDAY(i.created_at)) * 1440
            ), 1) as mttr_minutes
            FROM incidents i
            JOIN audit_log al ON al.target_id = i.id
                AND al.action = 'status_change'
                AND al.detail LIKE '%closed%'
            WHERE i.status = 'closed'
        """).fetchone()

        # Open incident durations
        open_rows = conn.execute("""
            SELECT id, title, source_ip, created_at,
                   ROUND((JULIANDAY('now') - JULIANDAY(created_at)) * 1440, 0) as open_minutes
            FROM incidents
            WHERE status = 'open'
            ORDER BY created_at ASC
        """).fetchall()

    mttd = mttd_row["mttd_minutes"] if mttd_row and mttd_row["mttd_minutes"] else 0
    mttr = mttr_row["mttr_minutes"] if mttr_row and mttr_row["mttr_minutes"] else 0
    return {
        "mttd_minutes": mttd,
        "mttr_minutes": mttr,
        "open_incidents": [dict(r) for r in open_rows],
    }


@router.get("/fp-stats")
def fp_stats():
    """Return false positive counts and rates for alerts and incidents."""
    with get_connection() as conn:
        alert_total = conn.execute("SELECT COUNT(*) as c FROM alerts").fetchone()["c"]
        alert_fp    = conn.execute("SELECT COUNT(*) as c FROM alerts WHERE false_positive = 1").fetchone()["c"]
        inc_total   = conn.execute("SELECT COUNT(*) as c FROM incidents").fetchone()["c"]
        inc_fp      = conn.execute("SELECT COUNT(*) as c FROM incidents WHERE false_positive = 1").fetchone()["c"]
        # FP marked this week
        fp_this_week = conn.execute("""
            SELECT COUNT(*) as c FROM audit_log
            WHERE action = 'fp_marked'
              AND created_at >= DATE('now', '-7 days')
        """).fetchone()["c"]
        # Top rules generating FPs
        top_fp_rules = conn.execute("""
            SELECT rule_name, COUNT(*) as fp_count
            FROM alerts WHERE false_positive = 1
            GROUP BY rule_name ORDER BY fp_count DESC LIMIT 5
        """).fetchall()
    return {
        "alert_total":    alert_total,
        "alert_fp":       alert_fp,
        "alert_fp_rate":  round(alert_fp / alert_total * 100, 1) if alert_total else 0,
        "inc_total":      inc_total,
        "inc_fp":         inc_fp,
        "inc_fp_rate":    round(inc_fp / inc_total * 100, 1) if inc_total else 0,
        "fp_this_week":   fp_this_week,
        "top_fp_rules":   [dict(r) for r in top_fp_rules],
    }


@router.get("/risk-trend")
def risk_trend(days: int = Query(7, ge=1, le=90)):
    """Return average and max risk score per day for the last N days."""
    from storage import get_connection
    import datetime
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT DATE(created_at) as day,
                   ROUND(AVG(risk_score), 1) as avg_risk,
                   MAX(risk_score) as max_risk,
                   COUNT(*) as alert_count
            FROM alerts
            WHERE created_at >= DATE('now', ?)
            GROUP BY DATE(created_at)
            ORDER BY day ASC
            """,
            (f"-{days} days",)
        ).fetchall()
    return [dict(r) for r in rows]
