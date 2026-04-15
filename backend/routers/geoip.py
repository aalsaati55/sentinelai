"""
routers/geoip.py

GET /api/geoip/lookup?ip=<ip>         — single IP lookup
POST /api/geoip/bulk  { "ips": [...] } — bulk lookup (max 50)
GET /api/geoip/map                     — all distinct source IPs from alerts with geo data
"""

import logging
from fastapi import APIRouter, Query, HTTPException
from pydantic import BaseModel
from typing import List

from geoip import lookup_ip, bulk_lookup
from storage import get_alerts, get_connection

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/geoip", tags=["geoip"])


class BulkRequest(BaseModel):
    ips: List[str]


@router.get("/lookup")
def geo_lookup(ip: str = Query(..., description="IPv4 address to look up")):
    if not ip:
        raise HTTPException(status_code=400, detail="ip parameter required")
    return lookup_ip(ip)


@router.post("/bulk")
def geo_bulk(body: BulkRequest):
    if len(body.ips) > 50:
        raise HTTPException(status_code=400, detail="Max 50 IPs per request")
    return bulk_lookup(body.ips)


@router.get("/map")
def geo_map():
    """
    Return geo data for all distinct source IPs found in alerts AND
    high-abuse IPs from the threat intel cache (score >= 75).
    Used to power the attack map page.
    """
    alerts = get_alerts(limit=1000)
    alert_ips = {a.get("source_ip") for a in alerts if a.get("source_ip")}

    # Pull high-abuse IPs from threat intel cache
    with get_connection() as conn:
        ti_rows = conn.execute(
            "SELECT ip, abuse_score, isp FROM threat_intel_cache WHERE abuse_score >= 75"
        ).fetchall()
    ti_map = {row["ip"]: row for row in ti_rows}
    ti_ips = set(ti_map.keys())

    all_ips = list(alert_ips | ti_ips)
    results = bulk_lookup(all_ips)

    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    points = []
    for ip, geo in results.items():
        if geo.get("lat") is None or geo.get("lon") is None:
            continue

        # Severity: use worst alert severity if available, else derive from TI score
        if ip in alert_ips:
            count = sum(1 for a in alerts if a.get("source_ip") == ip)
            worst = max(
                (a.get("severity", "low") for a in alerts if a.get("source_ip") == ip),
                key=lambda s: sev_order.get(s, 0),
                default="low",
            )
        else:
            count = 0
            score = ti_map[ip]["abuse_score"]
            worst = "critical" if score >= 90 else "high"

        isp = geo.get("isp") or (ti_map[ip]["isp"] if ip in ti_map else None)
        from_ti = ip in ti_ips and ip not in alert_ips
        points.append({
            "ip":           ip,
            "country":      geo["country"],
            "country_code": geo["country_code"],
            "city":         geo["city"],
            "lat":          geo["lat"],
            "lon":          geo["lon"],
            "isp":          isp,
            "alert_count":  count,
            "severity":     worst,
            "from_ti":      from_ti,
        })

    return {"points": points, "total": len(points)}
