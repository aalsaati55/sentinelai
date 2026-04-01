"""
normalizer.py

Provides build_event() — the single function all parsers call to produce
a normalized event dict in the project's common event format.

Common event format:
{
    "timestamp":   str   — ISO 8601 (YYYY-MM-DDTHH:MM:SS)
    "log_source":  str   — LogSource constant
    "event_type":  str   — EventType constant
    "source_ip":   str | None
    "username":    str | None
    "hostname":    str | None
    "status":      str   — EventStatus constant
    "message":     str   — human-readable description
    "raw_log":     str   — original unparsed line
}
"""

from typing import Optional, Dict, Any
from config import EventStatus


def build_event(
    timestamp: str,
    log_source: str,
    event_type: str,
    source_ip: Optional[str],
    username: Optional[str],
    hostname: Optional[str],
    status: str,
    message: str,
    raw_log: str,
) -> Dict[str, Any]:
    """
    Build and return a normalized event dict.

    All parsers must go through this function — it guarantees
    every event has the same structure regardless of source.
    """
    return {
        "timestamp":  timestamp,
        "log_source": log_source,
        "event_type": event_type,
        "source_ip":  source_ip or None,
        "username":   username or None,
        "hostname":   hostname or None,
        "status":     status if status else EventStatus.UNKNOWN,
        "message":    message,
        "raw_log":    raw_log,
    }
