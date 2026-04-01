"""
parser_syslog.py

Parses lines from /var/log/syslog (Ubuntu/Debian).

Supported event types:
    - service_started       (systemd: Started ...)
    - service_stopped       (systemd: Stopped ...)
    - service_failed        (systemd: Failed / failed with result)
    - kernel_event          (kernel: messages)
    - cron_job              (CRON / cron CMD entries)
    - system_error          (error / warning / critical keywords)
"""

import re
import logging
from typing import Optional, Dict, Any

from config import LogSource, EventType, EventStatus
from normalizer import build_event

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# syslog timestamp format (no year):
#   Mar 25 03:00:01 hostname process[pid]: message
# ──────────────────────────────────────────────

_PREFIX = r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+):\s+"

# systemd: Started <unit>
RE_SERVICE_STARTED = re.compile(
    _PREFIX + r"Started (.+)\.",
    re.IGNORECASE,
)

# systemd: Stopped <unit> / Stopping <unit>
RE_SERVICE_STOPPED = re.compile(
    _PREFIX + r"(?:Stopped|Stopping) (.+)\.",
    re.IGNORECASE,
)

# systemd: Failed to start <unit> / <unit> failed with result
RE_SERVICE_FAILED = re.compile(
    _PREFIX + r"(?:Failed to start (.+)\.|(\S+\.service): [Ff]ailed with result)",
    re.IGNORECASE,
)

# kernel: any kernel message (process = kernel)
RE_KERNEL = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+kernel:\s+(.+)",
    re.IGNORECASE,
)

# CRON job execution line
RE_CRON = re.compile(
    _PREFIX + r"\((\S+)\) CMD \((.+)\)",
    re.IGNORECASE,
)

# General error / warning / critical lines (catch-all for anomalies)
RE_SYSTEM_ERROR = re.compile(
    _PREFIX + r".*(error|warning|critical|panic|segfault|oom|killed).*",
    re.IGNORECASE,
)


# ──────────────────────────────────────────────
# Timestamp normalizer (same approach as parser_auth)
# ──────────────────────────────────────────────
def _normalize_timestamp(raw_ts: str) -> str:
    from dateutil import parser as dateparser
    try:
        dt = dateparser.parse(raw_ts, fuzzy=True)
        return dt.strftime("%Y-%m-%dT%H:%M:%S")
    except Exception:
        return raw_ts


# ──────────────────────────────────────────────
# Individual pattern handlers
# ──────────────────────────────────────────────

def _try_service_started(line: str) -> Optional[Dict[str, Any]]:
    m = RE_SERVICE_STARTED.match(line)
    if not m:
        return None
    ts, hostname, process, unit = m.group(1), m.group(2), m.group(3), m.group(4)
    return build_event(
        timestamp=_normalize_timestamp(ts),
        log_source=LogSource.SYSLOG,
        event_type=EventType.SERVICE_STARTED,
        source_ip=None,
        username=None,
        hostname=hostname,
        status=EventStatus.SUCCESS,
        message=f"Service started: {unit.strip()}",
        raw_log=line,
    )


def _try_service_stopped(line: str) -> Optional[Dict[str, Any]]:
    if RE_SERVICE_STARTED.match(line):
        return None  # avoid overlap
    m = RE_SERVICE_STOPPED.match(line)
    if not m:
        return None
    ts, hostname, process, unit = m.group(1), m.group(2), m.group(3), m.group(4)
    return build_event(
        timestamp=_normalize_timestamp(ts),
        log_source=LogSource.SYSLOG,
        event_type=EventType.SERVICE_STOPPED,
        source_ip=None,
        username=None,
        hostname=hostname,
        status=EventStatus.SUCCESS,
        message=f"Service stopped: {unit.strip()}",
        raw_log=line,
    )


def _try_service_failed(line: str) -> Optional[Dict[str, Any]]:
    m = RE_SERVICE_FAILED.match(line)
    if not m:
        return None
    ts, hostname = m.group(1), m.group(2)
    unit = (m.group(4) or m.group(5) or "unknown").strip()
    return build_event(
        timestamp=_normalize_timestamp(ts),
        log_source=LogSource.SYSLOG,
        event_type=EventType.SERVICE_FAILED,
        source_ip=None,
        username=None,
        hostname=hostname,
        status=EventStatus.FAILURE,
        message=f"Service failed: {unit}",
        raw_log=line,
    )


def _try_kernel(line: str) -> Optional[Dict[str, Any]]:
    m = RE_KERNEL.match(line)
    if not m:
        return None
    ts, hostname, kmsg = m.group(1), m.group(2), m.group(3)
    return build_event(
        timestamp=_normalize_timestamp(ts),
        log_source=LogSource.SYSLOG,
        event_type=EventType.KERNEL_EVENT,
        source_ip=None,
        username=None,
        hostname=hostname,
        status=EventStatus.UNKNOWN,
        message=f"Kernel: {kmsg[:200]}",
        raw_log=line,
    )


def _try_cron(line: str) -> Optional[Dict[str, Any]]:
    m = RE_CRON.match(line)
    if not m:
        return None
    ts, hostname, _proc, username, command = (
        m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
    )
    return build_event(
        timestamp=_normalize_timestamp(ts),
        log_source=LogSource.SYSLOG,
        event_type=EventType.CRON_JOB,
        source_ip=None,
        username=username,
        hostname=hostname,
        status=EventStatus.SUCCESS,
        message=f"Cron job executed by '{username}': {command[:200]}",
        raw_log=line,
    )


def _try_system_error(line: str) -> Optional[Dict[str, Any]]:
    m = RE_SYSTEM_ERROR.match(line)
    if not m:
        return None
    ts, hostname = m.group(1), m.group(2)
    return build_event(
        timestamp=_normalize_timestamp(ts),
        log_source=LogSource.SYSLOG,
        event_type=EventType.SYSTEM_ERROR,
        source_ip=None,
        username=None,
        hostname=hostname,
        status=EventStatus.FAILURE,
        message=f"System error/warning detected: {line[40:200]}",
        raw_log=line,
    )


# ──────────────────────────────────────────────
# Ordered handler list
# ──────────────────────────────────────────────
_HANDLERS = [
    _try_kernel,          # check kernel first (different prefix pattern)
    _try_service_failed,  # check failed before started/stopped to avoid overlap
    _try_service_started,
    _try_service_stopped,
    _try_cron,
    _try_system_error,    # broad catch-all last
]


def parse_syslog_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Public entry point called by collector.py.

    Tries each handler in order against the given syslog line.
    Returns the first matching normalized event dict, or None.
    """
    for handler in _HANDLERS:
        result = handler(line)
        if result is not None:
            return result
    return None
