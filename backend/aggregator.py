"""
aggregator.py

Groups normalized events into time-windowed sessions.

A session is a group of events sharing the same (source_ip, username) key
that fall within a configurable time window (default: 5 minutes).

Each session dict is the unit consumed by detection.py and anomaly_scoring.py.

Session structure:
{
    "session_key":          str     — "<ip>|<username>"
    "source_ip":            str | None
    "username":             str | None
    "window_start":         str     — ISO timestamp of first event
    "window_end":           str     — ISO timestamp of last event
    "activity_hour":        int     — hour of day of first event (0–23)
    "events":               list    — all raw event dicts in the session
    "event_count":          int
    "failed_login_count":   int
    "success_login_count":  int
    "invalid_user_count":   int
    "sudo_count":           int
    "custom_event_count":   int
    "unique_usernames":     int     — distinct usernames seen in session
    "event_rate":           float   — events per minute
    "success_after_failures": bool  — login_success appeared after login_failure(s)
    "privilege_after_login":  bool  — sudo appeared after a login_success
}
"""

import logging
from datetime import datetime, timedelta
from collections import defaultdict
from typing import List, Dict, Any, Optional

from config import (
    EventType,
    AGGREGATION_WINDOW_SECONDS,
    BRUTE_FORCE_THRESHOLD,
)

# Threshold: how many blocked ports from same IP = port scan
PORT_SCAN_THRESHOLD = 5

logger = logging.getLogger(__name__)

# Event types counted toward each feature
_FAILURE_TYPES         = {EventType.LOGIN_FAILURE, EventType.LOGIN_INVALID_USER}  # any auth failure
_PASSWORD_FAIL_TYPES   = {EventType.LOGIN_FAILURE}                               # wrong password only (real user)
_SUCCESS_TYPES         = {EventType.LOGIN_SUCCESS}
_INVALID_TYPES         = {EventType.LOGIN_INVALID_USER}
_SUDO_TYPES     = {EventType.SUDO_SUCCESS, EventType.SUDO_FAILURE,
                   EventType.SUDO_SESSION_OPENED}
_CUSTOM_TYPES   = {EventType.FILE_ACCESS, EventType.FILE_MODIFIED,
                   EventType.SENSITIVE_COMMAND, EventType.NETWORK_ANOMALY,
                   EventType.CUSTOM_ALERT}
_PORT_SCAN_TYPES = {EventType.PORT_SCAN}


# ──────────────────────────────────────────────
# Timestamp helpers
# ──────────────────────────────────────────────

def _parse_ts(ts: str) -> Optional[datetime]:
    """Parse an ISO timestamp string into a datetime object."""
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S")
    except (ValueError, TypeError):
        return None


def _session_key(event: Dict[str, Any]) -> str:
    """Build a grouping key from source_ip and username."""
    ip   = event.get("source_ip") or "unknown_ip"
    user = event.get("username")  or "unknown_user"
    return f"{ip}|{user}"


# ──────────────────────────────────────────────
# Session builder
# ──────────────────────────────────────────────

def _build_session(key: str, events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build a session feature dict from a list of events sharing the same key."""
    parts    = key.split("|", 1)
    src_ip   = parts[0] if parts[0] != "unknown_ip"   else None
    username = parts[1] if parts[1] != "unknown_user" else None

    timestamps = [_parse_ts(e["timestamp"]) for e in events]
    timestamps = [t for t in timestamps if t is not None]

    window_start = min(timestamps) if timestamps else None
    window_end   = max(timestamps) if timestamps else None

    # Duration in minutes (minimum 1 to avoid division by zero)
    if window_start and window_end:
        duration_minutes = max((window_end - window_start).total_seconds() / 60, 1)
    else:
        duration_minutes = 1

    activity_hour = window_start.hour if window_start else 0

    # Feature counts
    event_types            = [e["event_type"] for e in events]
    failed_login_count     = sum(1 for t in event_types if t in _PASSWORD_FAIL_TYPES)  # wrong-password only
    any_failure_count      = sum(1 for t in event_types if t in _FAILURE_TYPES)        # all failures incl. invalid user
    success_login_count    = sum(1 for t in event_types if t in _SUCCESS_TYPES)
    invalid_user_count     = sum(1 for t in event_types if t in _INVALID_TYPES)
    sudo_count             = sum(1 for t in event_types if t in _SUDO_TYPES)
    custom_event_count     = sum(1 for t in event_types if t in _CUSTOM_TYPES)
    port_scan_count        = sum(1 for t in event_types if t in _PORT_SCAN_TYPES)
    new_user_count         = sum(1 for t in event_types if t == EventType.NEW_USER_CREATED)
    cron_mod_count         = sum(1 for t in event_types if t == EventType.CRON_MODIFICATION)
    sudo_failure_count     = sum(1 for t in event_types if t == EventType.SUDO_FAILURE)
    unique_usernames       = len({e.get("username") for e in events if e.get("username")})
    # Count distinct ports hit for port scan detection
    blocked_ports          = {e.get("message", "").split("port ")[-1].split()[0]
                               for e in events if e.get("event_type") == EventType.PORT_SCAN}
    unique_ports_scanned   = len(blocked_ports)
    event_rate             = round(len(events) / duration_minutes, 2)

    # Behavioral flags
    seen_failure  = False
    seen_success  = False
    seen_sudo     = False
    success_after_failures  = False
    privilege_after_login   = False

    for e in events:
        et = e["event_type"]
        if et in _FAILURE_TYPES:  # any failure (incl. invalid user) counts for success_after_failures
            seen_failure = True
        if et in _SUCCESS_TYPES:
            seen_success = True
            if seen_failure:
                success_after_failures = True
        if et in _SUDO_TYPES:
            seen_sudo = True
            if seen_success:
                privilege_after_login = True

    return {
        "session_key":             key,
        "source_ip":               src_ip,
        "username":                username,
        "window_start":            window_start.strftime("%Y-%m-%dT%H:%M:%S") if window_start else "",
        "window_end":              window_end.strftime("%Y-%m-%dT%H:%M:%S")   if window_end   else "",
        "activity_hour":           activity_hour,
        "events":                  events,
        "event_count":             len(events),
        "failed_login_count":      failed_login_count,       # wrong password on real user only
        "any_failure_count":       any_failure_count,        # all auth failures incl. invalid user
        "success_login_count":     success_login_count,
        "invalid_user_count":      invalid_user_count,
        "sudo_count":              sudo_count,
        "sudo_failure_count":      sudo_failure_count,
        "custom_event_count":      custom_event_count,
        "port_scan_count":         port_scan_count,
        "unique_ports_scanned":    unique_ports_scanned,
        "new_user_count":          new_user_count,
        "cron_mod_count":          cron_mod_count,
        "unique_usernames":        unique_usernames,
        "event_rate":              event_rate,
        "success_after_failures":  success_after_failures,
        "privilege_after_login":   privilege_after_login,
        "ip_had_recent_failures":  False,  # populated post-build in aggregate_events
        "ip_invalid_user_count":   0,      # populated post-build: total invalid-user attempts from this IP
    }


# ──────────────────────────────────────────────
# Main aggregation function
# ──────────────────────────────────────────────

def aggregate_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Group events into time-windowed sessions by (source_ip, username).

    Events are first sorted by timestamp, then split into windows of
    AGGREGATION_WINDOW_SECONDS. A new window opens for a key whenever
    the gap between consecutive events exceeds the window size.

    Returns a list of session dicts, each containing aggregated features
    ready for detection and ML scoring.
    """
    if not events:
        return []

    # Sort events chronologically
    sorted_events = sorted(
        events,
        key=lambda e: e.get("timestamp", ""),
    )

    # Group by session key (ip|username), split on time gaps
    # buckets: { session_key: [ [events_in_window1], [events_in_window2], ... ] }
    buckets: Dict[str, List[List[Dict[str, Any]]]] = defaultdict(list)

    # last_ts tracks the last event timestamp per key
    last_ts: Dict[str, Optional[datetime]] = {}

    for event in sorted_events:
        key = _session_key(event)
        ts  = _parse_ts(event.get("timestamp", ""))

        if key not in last_ts or last_ts[key] is None:
            # First event for this key — open a new window
            buckets[key].append([event])
        else:
            gap = (ts - last_ts[key]).total_seconds() if ts else 0
            if gap > AGGREGATION_WINDOW_SECONDS:
                # Gap exceeded — open a new window
                buckets[key].append([event])
            else:
                # Still within window — append to current window
                buckets[key][-1].append(event)

        last_ts[key] = ts

    # Build session dicts from each bucket window
    sessions: List[Dict[str, Any]] = []
    for key, windows in buckets.items():
        for window_events in windows:
            session = _build_session(key, window_events)
            sessions.append(session)

    # Second pass: compute cross-session IP-level counters.
    # Sort sessions by window_start so we process chronologically.
    sessions.sort(key=lambda s: s.get("window_start", ""))

    # Tally total invalid-user attempts per IP across ALL sessions (different usernames)
    from collections import defaultdict as _dd
    ip_invalid_totals: dict = _dd(int)
    for session in sessions:
        ip = session.get("source_ip")
        if ip:
            ip_invalid_totals[ip] += session.get("invalid_user_count", 0)

    # Apply ip_invalid_user_count and ip_had_recent_failures to each session
    ips_with_failures: set = set()
    for session in sessions:
        ip = session.get("source_ip")
        if ip:
            session["ip_invalid_user_count"] = ip_invalid_totals[ip]
            if ip in ips_with_failures:
                session["ip_had_recent_failures"] = True
        # Register this IP as having password failures if it hit brute-force threshold
        if ip and session.get("failed_login_count", 0) >= BRUTE_FORCE_THRESHOLD:
            ips_with_failures.add(ip)

    logger.info(f"Aggregated {len(sorted_events)} events into {len(sessions)} sessions.")
    return sessions
