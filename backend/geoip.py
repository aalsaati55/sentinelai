"""
geoip.py

Resolves IPv4 addresses to country / city / lat-lon using ip-api.com (free tier).
Results are cached in memory to avoid hammering the API (rate limit: 45 req/min).

Usage:
    from geoip import lookup_ip
    info = lookup_ip("1.2.3.4")
    # {"ip": "1.2.3.4", "country": "China", "country_code": "CN",
    #  "city": "Beijing", "lat": 39.9, "lon": 116.4, "isp": "...", "cached": True}
"""

import logging
import urllib.request
import urllib.error
import json
import time
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

# In-memory cache: ip -> (result_dict, timestamp)
_cache: Dict[str, tuple] = {}
_CACHE_TTL = 3600  # 1 hour

# IPs that should never be looked up
_PRIVATE_PREFIXES = ("10.", "192.168.", "127.", "172.16.", "172.17.", "172.18.",
                     "172.19.", "172.2", "172.3", "::1", "fc", "fd")


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


# Fixed display coordinates for private/RFC-1918 subnets (used in map only)
_PRIVATE_GEO = {
    "10.":       {"country": "Private Network (10.x)",      "country_code": "--", "city": "LAN",     "lat": 20.0,  "lon": -30.0,  "isp": "Internal"},
    "192.168.":  {"country": "Private Network (192.168.x)", "country_code": "--", "city": "LAN",     "lat": 25.0,  "lon": -35.0,  "isp": "Internal"},
    "172.":      {"country": "Private Network (172.x)",     "country_code": "--", "city": "LAN",     "lat": 15.0,  "lon": -25.0,  "isp": "Internal"},
    "127.":      {"country": "Localhost",                   "country_code": "--", "city": "Loopback", "lat": 0.0,   "lon": 0.0,    "isp": "Loopback"},
}


def _empty(ip: str, reason: str = "private") -> Dict[str, Any]:
    return {
        "ip": ip,
        "country": None,
        "country_code": None,
        "city": None,
        "lat": None,
        "lon": None,
        "isp": None,
        "cached": False,
        "reason": reason,
    }


def _private_geo(ip: str) -> Dict[str, Any]:
    """Return a display-friendly geo dict for private/RFC-1918 IPs."""
    for prefix, geo in _PRIVATE_GEO.items():
        if ip.startswith(prefix):
            return {
                "ip":           ip,
                "country":      geo["country"],
                "country_code": geo["country_code"],
                "city":         geo["city"],
                "lat":          geo["lat"],
                "lon":          geo["lon"],
                "isp":          geo["isp"],
                "cached":       False,
                "reason":       "private",
            }
    return _empty(ip, "private")


def lookup_ip(ip: str) -> Dict[str, Any]:
    """
    Look up geolocation for an IP address.
    Returns a dict with country, city, lat/lon, and ISP.
    Private / loopback IPs return a placeholder location so they appear on the map.
    """
    if not ip:
        return _empty("", "empty")

    if _is_private(ip):
        return _private_geo(ip)

    # Check cache
    if ip in _cache:
        result, ts = _cache[ip]
        if time.time() - ts < _CACHE_TTL:
            result["cached"] = True
            return result

    url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp,query"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SentinelAI/1.0"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:
        logger.warning(f"GeoIP lookup failed for {ip}: {e}")
        return _empty(ip, "lookup_failed")

    if data.get("status") != "success":
        return _empty(ip, data.get("message", "failed"))

    result = {
        "ip":           ip,
        "country":      data.get("country"),
        "country_code": data.get("countryCode"),
        "city":         data.get("city"),
        "lat":          data.get("lat"),
        "lon":          data.get("lon"),
        "isp":          data.get("isp"),
        "cached":       False,
        "reason":       None,
    }
    _cache[ip] = (result, time.time())
    logger.debug(f"GeoIP: {ip} -> {result['city']}, {result['country']}")
    return result


def bulk_lookup(ips: list) -> Dict[str, Dict[str, Any]]:
    """Look up a list of IPs, returning a dict keyed by IP."""
    return {ip: lookup_ip(ip) for ip in set(ips) if ip}
