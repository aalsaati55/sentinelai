"""
routers/threatintel.py

GET /api/threatintel/{ip}  — query AbuseIPDB for IP reputation, cache result in DB
GET /api/threatintel/bulk  — batch lookup for multiple IPs
"""

import asyncio
import logging
import requests
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List

from storage import get_connection, add_to_watchlist, is_ip_watchlisted, was_watchlist_manually_removed, clear_watchlist_removed
from auth import get_current_user
from utils import now_iso
from ws_manager import manager as ws_manager

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/threatintel", tags=["threatintel"])

ABUSEIPDB_KEY = "c5f2fc64a844d6232d1e2561a028478e57284b10f52fbab45500c0c2472010706813dfce535b8332"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# Abuse category codes → human readable labels
ABUSE_CATEGORIES = {
    1:  "DNS Compromise",
    2:  "DNS Poisoning",
    3:  "Fraud Orders",
    4:  "DDoS Attack",
    5:  "FTP Brute-Force",
    6:  "Ping of Death",
    7:  "Phishing",
    8:  "Fraud VoIP",
    9:  "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH Brute-Force",
    23: "IoT Targeted",
}

CACHE_TTL_HOURS = 24


def _get_cached(ip: str):
    with get_connection() as conn:
        row = conn.execute(
            """SELECT * FROM threat_intel_cache
               WHERE ip = ?
               AND datetime(cached_at) > datetime('now', ?)""",
            (ip, f"-{CACHE_TTL_HOURS} hours"),
        ).fetchone()
    return dict(row) if row else None


def _save_cache(ip: str, data: dict):
    with get_connection() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO threat_intel_cache
               (ip, abuse_score, total_reports, country_code, isp, domain,
                is_tor, categories, last_reported_at, cached_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                ip,
                data.get("abuseConfidenceScore", 0),
                data.get("totalReports", 0),
                data.get("countryCode", ""),
                data.get("isp", ""),
                data.get("domain", ""),
                1 if data.get("isTor") else 0,
                ",".join(str(c) for c in (data.get("reports") and
                    list({r["categories"][0] for r in data["reports"] if r.get("categories")}) or [])),
                data.get("lastReportedAt", ""),
                now_iso(),
            ),
        )


def _fetch_from_abuseipdb(ip: str) -> dict:
    try:
        resp = requests.get(
            ABUSEIPDB_URL,
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=8,
        )
        resp.raise_for_status()
        return resp.json().get("data", {})
    except requests.RequestException as e:
        logger.warning(f"AbuseIPDB lookup failed for {ip}: {e}")
        return {}


async def _broadcast_watchlist(ip: str) -> None:
    """Fire a WebSocket 'watchlist' event so connected clients update in real-time."""
    try:
        await ws_manager.broadcast({"type": "watchlist", "data": {"ip": ip}})
    except Exception:
        pass


def _ensure_ti_incident(ip: str, score: int, data: dict) -> None:
    """Create a Threat Intelligence incident for this IP if one doesn't already exist."""
    with get_connection() as conn:
        existing = conn.execute(
            """SELECT id FROM incidents
               WHERE source_ip = ? AND title LIKE 'Threat Intelligence:%'
               AND status IN ('open','investigating')""",
            (ip,),
        ).fetchone()
        if existing:
            return

        isp      = data.get("isp", "Unknown ISP")
        country  = data.get("countryCode", "??")
        reports  = data.get("totalReports", 0)
        tor_note = " (Tor exit node)" if data.get("isTor", False) else ""

        title = f"Threat Intelligence: {ip} flagged by AbuseIPDB"
        description = (
            f"IP {ip}{tor_note} scored {score}% abuse confidence on AbuseIPDB "
            f"with {reports} total reports. ISP: {isp}, Country: {country}. "
            f"Automatically created by the Threat Intelligence engine."
        )
        conn.execute(
            """INSERT INTO incidents
               (title, description, source_ip, username, risk_score, anomaly_level, status, created_at)
               VALUES (?, ?, ?, NULL, ?, 'high', 'open', ?)""",
            (title, description, ip, min(score, 100), now_iso()),
        )
    logger.info(f"Auto-created TI incident for {ip} (score={score}%)")
    # Broadcast to all connected dashboard clients so Incidents page updates in real-time
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.ensure_future(ws_manager.broadcast({
                "type": "incident",
                "data": {"source_ip": ip, "title": title, "risk_score": min(score, 100), "status": "open"},
            }))
    except Exception:
        pass


def lookup_ip(ip: str) -> dict:
    """Lookup IP — returns cached result or fetches fresh from AbuseIPDB."""
    cached = _get_cached(ip)
    if cached:
        cached["from_cache"] = True
        cached["categories"] = [
            ABUSE_CATEGORIES.get(int(c), f"Category {c}")
            for c in (cached.get("categories") or "").split(",")
            if c
        ]
        # Still enforce watchlist even on cache hits (handles re-adds after manual removal)
        score = cached.get("abuse_score", 0)
        if score >= 75 and not is_ip_watchlisted(ip):
            try:
                if was_watchlist_manually_removed(ip):
                    clear_watchlist_removed(ip)
                add_to_watchlist(ip, f"AbuseIPDB confidence {score}% — auto-flagged threat", added_by="threatintel")
            except Exception:
                pass
        return cached

    data = _fetch_from_abuseipdb(ip)
    if not data:
        return {"ip": ip, "abuse_score": 0, "total_reports": 0, "error": "lookup failed"}

    _save_cache(ip, data)

    score = data.get("abuseConfidenceScore", 0)

    # Auto-add to watchlist if confidence >= 75%
    # For high-confidence threats we override manual removals — the IP is dangerous
    if score >= 75 and not is_ip_watchlisted(ip):
        try:
            if was_watchlist_manually_removed(ip):
                clear_watchlist_removed(ip)
            add_to_watchlist(ip, f"AbuseIPDB confidence {score}% — auto-flagged threat", added_by="threatintel")
        except Exception:
            pass

    # Auto-create a Threat Intelligence incident if score >= 75
    if score >= 75:
        try:
            _ensure_ti_incident(ip, score, data)
        except Exception as e:
            logger.warning(f"Failed to create TI incident for {ip}: {e}")

    # Build category list from verbose reports
    cat_ids = list({
        c
        for r in (data.get("reports") or [])
        for c in (r.get("categories") or [])
    })
    categories = [ABUSE_CATEGORIES.get(c, f"Category {c}") for c in cat_ids]

    return {
        "ip": ip,
        "abuse_score": score,
        "total_reports": data.get("totalReports", 0),
        "country_code": data.get("countryCode", ""),
        "isp": data.get("isp", ""),
        "domain": data.get("domain", ""),
        "is_tor": data.get("isTor", False),
        "last_reported_at": data.get("lastReportedAt", ""),
        "categories": categories,
        "from_cache": False,
    }


@router.get("/{ip}")
async def get_threat_intel(ip: str, current_user: dict = Depends(get_current_user)):
    result = lookup_ip(ip)
    score = result.get("abuse_score", 0)
    if score >= 75:
        await _broadcast_watchlist(ip)
    return result


class BulkRequest(BaseModel):
    ips: List[str]


@router.post("/bulk")
async def bulk_threat_intel(body: BulkRequest, current_user: dict = Depends(get_current_user)):
    results = {}
    broadcast_ips = []
    for ip in body.ips[:20]:  # cap at 20 to protect quota
        if ip:
            r = lookup_ip(ip)
            results[ip] = r
            if r.get("abuse_score", 0) >= 75:
                broadcast_ips.append(ip)
    for ip in broadcast_ips:
        await _broadcast_watchlist(ip)
    return results
