"""
parser_auth.py

Parses lines from /var/log/auth.log (Ubuntu/Debian).

Each parse function targets a specific pattern found in auth.log.
All functions return a normalized event dict or None if the line
does not match.

Supported event types:
    - login_failure          (Failed password)
    - login_invalid_user     (Invalid user)
    - login_success          (Accepted password / publickey)
    - sudo_success           (sudo command executed)
    - sudo_failure           (sudo: authentication failure)
    - sudo_session_opened    (sudo: pam_unix session opened)
    - sudo_session_closed    (sudo: pam_unix session closed)
    - session_opened         (sshd / login session opened)
    - session_closed         (sshd / login session closed)
    - logout                 (Disconnected / disconnecting)
"""

import re
import logging
from typing import Optional, Dict, Any

from config import LogSource, EventType, EventStatus
from normalizer import build_event

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Compiled regex patterns for auth.log
#
# auth.log timestamp format (no year):
#   Mar 25 03:00:01 hostname process[pid]: message
# ──────────────────────────────────────────────

# Common prefix: captures timestamp, hostname, process
_PREFIX = r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+):\s+"

# sshd: Failed password for <user> from <ip> port <port>
RE_FAILED_PASSWORD = re.compile(
    _PREFIX + r"Failed password for (?:invalid user )?(\S+) from ([\d\.]+) port \d+ ssh2?",
    re.IGNORECASE,
)

# sshd: Invalid user <user> from <ip>
RE_INVALID_USER = re.compile(
    _PREFIX + r"Invalid user (\S+) from ([\d\.]+)",
    re.IGNORECASE,
)

# sshd: Accepted password/publickey for <user> from <ip>
RE_ACCEPTED = re.compile(
    _PREFIX + r"Accepted (?:password|publickey) for (\S+) from ([\d\.]+) port \d+ ssh2?",
    re.IGNORECASE,
)

# sudo: <user> : TTY=... ; USER=root ; COMMAND=<cmd>
RE_SUDO_COMMAND = re.compile(
    _PREFIX + r"(\S+)\s+:\s+TTY=\S+\s+;\s+PWD=\S+\s+;\s+USER=(\S+)\s+;\s+COMMAND=(.+)",
    re.IGNORECASE,
)

# sudo: pam_unix(sudo:auth): authentication failure; ... user=<user>
RE_SUDO_FAILURE = re.compile(
    _PREFIX + r"pam_unix\(sudo:auth\): authentication failure;.*?user=(\S+)",
    re.IGNORECASE,
)

# pam_unix(sshd:session) or pam_unix(sudo:session): session opened for user <user> by ...
RE_SESSION_OPENED = re.compile(
    _PREFIX + r"pam_unix\((\S+):session\): session opened for user (\S+)",
    re.IGNORECASE,
)

# pam_unix(...:session): session closed for user <user>
RE_SESSION_CLOSED = re.compile(
    _PREFIX + r"pam_unix\((\S+):session\): session closed for user (\S+)",
    re.IGNORECASE,
)

# sshd: Disconnected from / Disconnecting: user <user> <ip>
RE_DISCONNECTED = re.compile(
    _PREFIX + r"Disconnected from(?: authenticating)?(?: user (\S+))? ([\d\.]+) port \d+",
    re.IGNORECASE,
)


# ──────────────────────────────────────────────
# Timestamp normalizer
# auth.log has no year; we inject the current year for ISO format.
# ──────────────────────────────────────────────
def _normalize_timestamp(raw_ts: str) -> str:
    """Convert 'Mar 25 03:00:01' → '2026-03-25T03:00:01' (best-effort)."""
    from dateutil import parser as dateparser
    try:
        dt = dateparser.parse(raw_ts, fuzzy=True)
        return dt.strftime("%Y-%m-%dT%H:%M:%S")
    except Exception:
        return raw_ts  # fallback: keep original string


# ──────────────────────────────────────────────
# Individual pattern handlers
# Each returns a normalized event dict or None.
# ──────────────────────────────────────────────

def _try_failed_password(line: str) -> Optional[Dict[str, Any]]:
    m = RE_FAILED_PASSWORD.match(line)
    if not m:
        return None
    ts, hostname, process, username, src_ip = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)

    # Distinguish plain failure vs invalid user failure
    event_type = EventType.LOGIN_INVALID_USER if "invalid user" in line.lower() else EventType.LOGIN_FAILURE

    return build_event(
        timestamp=_normalize_timestamp(ts),
        log_source=LogSource.AUTH,
        event_type=event_type,
        source_ip=src_ip,
        username=username,
        hostname=hostname,
        status=EventStatus.FAILURE,
        message=f"Failed login attempt for user '{username}' from {src_ip}",
        raw_log=line,
    )


def _try_invalid_user(line: str) -> Optional[Dict[str, Any]]:
    """
    Catches 'Invalid user X from IP' lines that are NOT paired with
    a 'Failed password' line (some sshd versions emit both; others only one).
    """
    if "Failed password" in line:
        return None  # already handled by _try_failed_password
    m = RE_INVALID_USER.match(line)
    if not m:
        return None
    ts, hostname, _proc, username, src_ip = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
    return build_event(
        timestamp=_normalize_timestamp(ts),
        log_source=LogSource.AUTH,
        event_type=EventType.LOGIN_INVALID_USER,
        source_ip=src_ip,
        username=username,
        hostname=hostname,
        status=EventStatus.FAILURE,
        message=f"Login attempt with invalid user '{username}' from {src_ip}",
        raw_log=line,
    )


def _try_accepted(line: str) -> Optional[Dict[str, Any]]:
    m = RE_ACCEPTED.match(line)
    if not m:
        return None
    ts, hostname, _proc, username, src_ip = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
    return build_event(
        timestamp=_normalize_timestamp(ts),
        log_source=LogSource.AUTH,
        event_type=EventType.LOGIN_SUCCESS,
        source_ip=src_ip,
        username=username,
        hostname=hostname,
        status=EventStatus.SUCCESS,
        message=f"Successful login for user '{username}' from {src_ip}",
        raw_log=line,
    )


def _try_sudo_command(line: str) -> Optional[Dict[str, Any]]:
    m = RE_SUDO_COMMAND.match(line)
    if not m:
        return None
    ts, hostname, _proc, username, run_as_user, command = (
        m.group(1), m.group(2), m.group(3), m.group(4), m.group(5), m.group(6)
    )
    return build_event(
        timestamp=_normalize_timestamp(ts),
        log_source=LogSource.AUTH,
        event_type=EventType.SUDO_SUCCESS,
        source_ip=None,
        username=username,
        hostname=hostname,
        status=EventStatus.SUCCESS,
        message=f"User '{username}' ran sudo command as '{run_as_user}': {command.strip()}",
        raw_log=line,
    )


def _try_sudo_failure(line: str) -> Optional[Dict[str, Any]]:
    m = RE_SUDO_FAILURE.match(line)
    if not m:
        return None
    ts, hostname, _proc, username = m.group(1), m.group(2), m.group(3), m.group(4)
    return build_event(
        timestamp=_normalize_timestamp(ts),
        log_source=LogSource.AUTH,
        event_type=EventType.SUDO_FAILURE,
        source_ip=None,
        username=username,
        hostname=hostname,
        status=EventStatus.FAILURE,
        message=f"Sudo authentication failure for user '{username}'",
        raw_log=line,
    )


def _try_session_opened(line: str) -> Optional[Dict[str, Any]]:
    m = RE_SESSION_OPENED.match(line)
    if not m:
        return None
    ts, hostname, _proc, service, username = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
    # Distinguish sudo sessions from regular ssh/login sessions
    event_type = EventType.SUDO_SESSION_OPENED if "sudo" in service.lower() else EventType.SESSION_OPENED
    return build_event(
        timestamp=_normalize_timestamp(ts),
        log_source=LogSource.AUTH,
        event_type=event_type,
        source_ip=None,
        username=username,
        hostname=hostname,
        status=EventStatus.SUCCESS,
        message=f"Session opened for user '{username}' via {service}",
        raw_log=line,
    )


def _try_session_closed(line: str) -> Optional[Dict[str, Any]]:
    m = RE_SESSION_CLOSED.match(line)
    if not m:
        return None
    ts, hostname, _proc, service, username = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
    event_type = EventType.SUDO_SESSION_CLOSED if "sudo" in service.lower() else EventType.SESSION_CLOSED
    return build_event(
        timestamp=_normalize_timestamp(ts),
        log_source=LogSource.AUTH,
        event_type=event_type,
        source_ip=None,
        username=username,
        hostname=hostname,
        status=EventStatus.SUCCESS,
        message=f"Session closed for user '{username}' via {service}",
        raw_log=line,
    )


def _try_disconnected(line: str) -> Optional[Dict[str, Any]]:
    m = RE_DISCONNECTED.match(line)
    if not m:
        return None
    ts, hostname, _proc = m.group(1), m.group(2), m.group(3)
    username = m.group(4)  # may be None
    src_ip   = m.group(5)
    return build_event(
        timestamp=_normalize_timestamp(ts),
        log_source=LogSource.AUTH,
        event_type=EventType.LOGOUT,
        source_ip=src_ip,
        username=username,
        hostname=hostname,
        status=EventStatus.SUCCESS,
        message=f"Disconnected{' user ' + username if username else ''} from {src_ip}",
        raw_log=line,
    )


# ──────────────────────────────────────────────
# Ordered list of handlers.
# Each line is tried against every handler in order;
# the first match wins and we move on to the next line.
# ──────────────────────────────────────────────
_HANDLERS = [
    _try_failed_password,
    _try_invalid_user,
    _try_accepted,
    _try_sudo_command,
    _try_sudo_failure,
    _try_session_opened,
    _try_session_closed,
    _try_disconnected,
]


def parse_auth_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Public entry point called by collector.py.

    Tries each handler in order against the given auth.log line.
    Returns the first matching normalized event dict, or None if
    the line is not relevant to any known event type.
    """
    for handler in _HANDLERS:
        result = handler(line)
        if result is not None:
            return result
    return None  # line is not interesting (e.g. 'CRON', 'systemd-logind', etc.)
