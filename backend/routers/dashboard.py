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
