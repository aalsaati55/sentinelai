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
from storage import get_alerts

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
    Return geo data for all distinct source IPs found in alerts.
    Used to power the attack map page.
    """
    alerts = get_alerts(limit=1000)
    ips = list({a.get("source_ip") for a in alerts if a.get("source_ip")})
    results = bulk_lookup(ips)

    points = []
    for ip, geo in results.items():
        if geo.get("lat") is not None and geo.get("lon") is not None:
            # Count how many alerts came from this IP
            count = sum(1 for a in alerts if a.get("source_ip") == ip)
            # Worst severity from this IP
            sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            worst = max(
                (a.get("severity", "low") for a in alerts if a.get("source_ip") == ip),
                key=lambda s: sev_order.get(s, 0),
                default="low",
            )
            points.append({
                "ip":           ip,
                "country":      geo["country"],
                "country_code": geo["country_code"],
                "city":         geo["city"],
                "lat":          geo["lat"],
                "lon":          geo["lon"],
                "isp":          geo["isp"],
                "alert_count":  count,
                "severity":     worst,
            })

    return {"points": points, "total": len(points)}
