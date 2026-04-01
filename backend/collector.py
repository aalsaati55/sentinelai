"""
collector.py

Responsible for reading raw log files from disk and dispatching each line
to the correct parser based on log source type.

Supports: auth.log, syslog, custom_security.log
Returns a flat list of normalized event dicts ready for storage.
"""

import os
import logging
from typing import List, Dict, Any

from config import LogSource, AUTH_LOG_PATH, SYSLOG_PATH, CUSTOM_LOG_PATH
from parser_auth import parse_auth_line
from parser_syslog import parse_syslog_line
from parser_custom import parse_custom_line

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Registry: maps each log source to its parser function and file path.
# To add a new log source, register it here — no other file needs to change.
# ──────────────────────────────────────────────
LOG_SOURCE_REGISTRY: Dict[str, Dict] = {
    LogSource.AUTH: {
        "path":   AUTH_LOG_PATH,
        "parser": parse_auth_line,
    },
    LogSource.SYSLOG: {
        "path":   SYSLOG_PATH,
        "parser": parse_syslog_line,
    },
    LogSource.CUSTOM: {
        "path":   CUSTOM_LOG_PATH,
        "parser": parse_custom_line,
    },
}


def read_log_file(file_path: str) -> List[str]:
    """Read all lines from a log file. Returns empty list if file is missing."""
    if not os.path.exists(file_path):
        logger.warning(f"Log file not found, skipping: {file_path}")
        return []
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = [line.rstrip("\n") for line in f if line.strip()]
        logger.info(f"Read {len(lines)} lines from {file_path}")
        return lines
    except OSError as e:
        logger.error(f"Failed to read {file_path}: {e}")
        return []


def collect_source(source: str) -> List[Dict[str, Any]]:
    """
    Collect and parse all events from a single log source.

    Args:
        source: One of LogSource.AUTH / LogSource.SYSLOG / LogSource.CUSTOM

    Returns:
        List of normalized event dicts (None results from parser are dropped).
    """
    if source not in LOG_SOURCE_REGISTRY:
        logger.error(f"Unknown log source: '{source}'. Must be one of {list(LOG_SOURCE_REGISTRY.keys())}")
        return []

    entry   = LOG_SOURCE_REGISTRY[source]
    lines   = read_log_file(entry["path"])
    parser  = entry["parser"]
    events  = []

    for line in lines:
        try:
            event = parser(line)
            if event is not None:
                events.append(event)
        except Exception as e:
            logger.warning(f"[{source}] Parser error on line — {e} | Line: {line[:120]}")

    logger.info(f"[{source}] Collected {len(events)} events from {len(lines)} lines.")
    return events


def collect_all() -> List[Dict[str, Any]]:
    """
    Collect and parse events from ALL registered log sources.

    Returns:
        Combined list of normalized event dicts, sorted by timestamp ascending.
    """
    all_events: List[Dict[str, Any]] = []

    for source in LOG_SOURCE_REGISTRY:
        events = collect_source(source)
        all_events.extend(events)

    # Sort by timestamp so the pipeline processes events in chronological order
    all_events.sort(key=lambda e: e.get("timestamp", ""))

    logger.info(f"Total events collected across all sources: {len(all_events)}")
    return all_events
