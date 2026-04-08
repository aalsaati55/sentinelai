"""
routers/threatintel.py

GET /api/threatintel/{ip}  — query AbuseIPDB for IP reputation, cache result in DB
GET /api/threatintel/bulk  — batch lookup for multiple IPs
"""

import logging
import requests
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List

from storage import get_connection, add_to_watchlist, is_ip_watchlisted, was_watchlist_manually_removed
from auth import get_current_user
from utils import now_iso

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
        return cached

    data = _fetch_from_abuseipdb(ip)
    if not data:
        return {"ip": ip, "abuse_score": 0, "total_reports": 0, "error": "lookup failed"}

    _save_cache(ip, data)

    score = data.get("abuseConfidenceScore", 0)

    # Auto-add to watchlist if confidence >= 75%, but respect manual removals
    if score >= 75 and not is_ip_watchlisted(ip) and not was_watchlist_manually_removed(ip):
        try:
            add_to_watchlist(ip, f"AbuseIPDB confidence {score}% — auto-flagged threat", added_by="threatintel")
        except Exception:
            pass

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
def get_threat_intel(ip: str, current_user: dict = Depends(get_current_user)):
    return lookup_ip(ip)


class BulkRequest(BaseModel):
    ips: List[str]


@router.post("/bulk")
def bulk_threat_intel(body: BulkRequest, current_user: dict = Depends(get_current_user)):
    results = {}
    for ip in body.ips[:20]:  # cap at 20 to protect quota
        if ip:
            results[ip] = lookup_ip(ip)
    return results
