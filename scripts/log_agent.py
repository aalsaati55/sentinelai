#!/usr/bin/env python3
"""
log_agent.py

Runs on the Ubuntu target VM.
Continuously tails /var/log/auth.log and /var/log/syslog and ships
new lines to the SentinelAI backend in real time.

Usage:
    python3 log_agent.py --host 192.168.56.1 --port 8000

Arguments:
    --host      IP address of the Windows host running SentinelAI backend
    --port      Port of the backend (default: 8000)
    --interval  Seconds between polls (default: 2)
"""

import argparse
import time
import os
import sys
import json
import urllib.request
import urllib.error
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("log_agent")

LOG_SOURCES = {
    "auth":   "/var/log/auth.log",
    "syslog": "/var/log/syslog",
}

BATCH_SIZE = 50   # max lines per request


def post_batch(host: str, port: int, source: str, lines: list) -> bool:
    """POST a batch of log lines to the SentinelAI ingest endpoint."""
    url     = f"http://{host}:{port}/api/live/ingest"
    payload = json.dumps({"source": source, "lines": lines}).encode("utf-8")
    req     = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            result = json.loads(resp.read())
            if result.get("alerts", 0) > 0:
                logger.warning(
                    f"[{source}] {result['events']} events, "
                    f"{result['alerts']} ALERTS detected!"
                )
            else:
                logger.info(f"[{source}] Sent {result.get('events', 0)} events")
        return True
    except urllib.error.URLError as e:
        logger.error(f"Failed to reach backend at {url}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error posting batch: {e}")
        return False


def tail_file(path: str, last_pos: int) -> tuple:
    """
    Read new lines from a file since last_pos.
    Returns (new_lines, new_position).
    """
    if not os.path.exists(path):
        return [], last_pos

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            size = os.fstat(f.fileno()).st_size
            # File was rotated/truncated — reset to beginning
            if size < last_pos:
                logger.info(f"Log rotation detected for {path}, resetting.")
                last_pos = 0
            f.seek(last_pos)
            lines     = [line.rstrip("\n") for line in f if line.strip()]
            new_pos   = f.tell()
        return lines, new_pos
    except OSError as e:
        logger.error(f"Cannot read {path}: {e}")
        return [], last_pos


def run(host: str, port: int, interval: float):
    logger.info(f"SentinelAI Log Agent starting — backend: {host}:{port}")
    logger.info(f"Monitoring: {', '.join(LOG_SOURCES.values())}")
    logger.info(f"Poll interval: {interval}s")

    # Track file position for each source to only send NEW lines
    positions = {source: 0 for source in LOG_SOURCES}

    # Skip existing content on first run — only tail NEW lines from now
    for source, path in LOG_SOURCES.items():
        if os.path.exists(path):
            positions[source] = os.path.getsize(path)
            logger.info(f"[{source}] Starting from end of file (pos={positions[source]})")
        else:
            logger.warning(f"[{source}] File not found: {path} — will retry")

    logger.info("Agent ready. Waiting for new log entries...")

    while True:
        for source, path in LOG_SOURCES.items():
            lines, positions[source] = tail_file(path, positions[source])
            if not lines:
                continue

            # Send in batches
            for i in range(0, len(lines), BATCH_SIZE):
                batch = lines[i:i + BATCH_SIZE]
                post_batch(host, port, source, batch)

        time.sleep(interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SentinelAI Log Agent")
    parser.add_argument("--host",     default="192.168.56.1",   help="Backend host IP")
    parser.add_argument("--port",     default=8000, type=int,   help="Backend port")
    parser.add_argument("--interval", default=2.0,  type=float, help="Poll interval in seconds")
    args = parser.parse_args()

    try:
        run(args.host, args.port, args.interval)
    except KeyboardInterrupt:
        logger.info("Agent stopped.")
        sys.exit(0)
