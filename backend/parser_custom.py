"""
parser_custom.py

Parses lines from /var/log/sentinel/custom_security.log.
This log is written by a script on the monitored Ubuntu VM to capture
events that standard Linux logs don't cover well.

Supported formats
-----------------
1. JSON per line (preferred):
   {"timestamp": "2026-03-25T03:00:00", "event": "file_access",
    "user": "root", "path": "/etc/shadow", "ip": "192.168.1.50",
    "hostname": "ubuntu-vm", "details": "read attempt"}

2. Plain-text fallback (key=value):
   2026-03-25T03:00:00 SENTINEL event=file_access user=root ip=192.168.1.50 details=read /etc/shadow

Supported event types:
    - file_access           (read of a sensitive file)
    - file_modified         (write/modify of a sensitive file)
    - sensitive_command     (dangerous command execution)
    - network_anomaly       (unusual outbound connection)
    - custom_alert          (generic custom alert)
"""

import re
import json
import logging
from typing import Optional, Dict, Any

from config import LogSource, EventType, EventStatus
from normalizer import build_event

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Known event keyword → EventType mapping
# ──────────────────────────────────────────────
_EVENT_MAP = {
    "file_access":       EventType.FILE_ACCESS,
    "file_modified":     EventType.FILE_MODIFIED,
    "file_modify":       EventType.FILE_MODIFIED,
    "sensitive_command": EventType.SENSITIVE_COMMAND,
    "cmd":               EventType.SENSITIVE_COMMAND,
    "network_anomaly":   EventType.NETWORK_ANOMALY,
    "network":           EventType.NETWORK_ANOMALY,
    "custom_alert":      EventType.CUSTOM_ALERT,
    "alert":             EventType.CUSTOM_ALERT,
}

# Plain-text fallback pattern:
# 2026-03-25T03:00:00 SENTINEL event=file_access user=root ...
RE_PLAINTEXT = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+\S+\s+(.+)$"
)

# key=value extractor for plaintext lines
RE_KV = re.compile(r"(\w+)=(\S+)")


def _map_event_type(raw: str) -> str:
    """Map a raw event string from the log to a known EventType constant."""
    return _EVENT_MAP.get(raw.lower(), EventType.CUSTOM_ALERT)


def _status_from_event_type(event_type: str) -> str:
    """Infer status from event type."""
    if event_type in (EventType.FILE_ACCESS, EventType.FILE_MODIFIED,
                      EventType.SENSITIVE_COMMAND, EventType.NETWORK_ANOMALY,
                      EventType.CUSTOM_ALERT):
        return EventStatus.UNKNOWN
    return EventStatus.UNKNOWN


# ──────────────────────────────────────────────
# JSON format parser
# ──────────────────────────────────────────────

def _try_json(line: str) -> Optional[Dict[str, Any]]:
    """Parse a JSON-formatted custom log line."""
    if not line.startswith("{"):
        return None
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None

    raw_event = data.get("event", "custom_alert")
    event_type = _map_event_type(raw_event)

    path    = data.get("path", "")
    details = data.get("details", "")
    summary = f"{raw_event}"
    if path:
        summary += f" on '{path}'"
    if details:
        summary += f" — {details}"

    return build_event(
        timestamp=data.get("timestamp", ""),
        log_source=LogSource.CUSTOM,
        event_type=event_type,
        source_ip=data.get("ip"),
        username=data.get("user"),
        hostname=data.get("hostname"),
        status=EventStatus.UNKNOWN,
        message=summary,
        raw_log=line,
    )


# ──────────────────────────────────────────────
# Plain-text fallback parser
# ──────────────────────────────────────────────

def _try_plaintext(line: str) -> Optional[Dict[str, Any]]:
    """Parse a plain-text key=value formatted custom log line."""
    m = RE_PLAINTEXT.match(line)
    if not m:
        return None

    timestamp  = m.group(1)
    rest       = m.group(2)
    kv_pairs   = dict(RE_KV.findall(rest))

    raw_event  = kv_pairs.get("event", "custom_alert")
    event_type = _map_event_type(raw_event)
    details    = kv_pairs.get("details", rest[:200])

    return build_event(
        timestamp=timestamp,
        log_source=LogSource.CUSTOM,
        event_type=event_type,
        source_ip=kv_pairs.get("ip"),
        username=kv_pairs.get("user"),
        hostname=kv_pairs.get("hostname"),
        status=EventStatus.UNKNOWN,
        message=f"{raw_event} — {details}",
        raw_log=line,
    )


# ──────────────────────────────────────────────
# Ordered handler list
# ──────────────────────────────────────────────
_HANDLERS = [
    _try_json,
    _try_plaintext,
]


def parse_custom_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Public entry point called by collector.py.

    Tries JSON format first, then plain-text fallback.
    Returns a normalized event dict or None.
    """
    for handler in _HANDLERS:
        result = handler(line)
        if result is not None:
            return result
    return None
