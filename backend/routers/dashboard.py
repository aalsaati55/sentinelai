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
