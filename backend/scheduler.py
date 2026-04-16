"""
scheduler.py

Background daemon thread that fires the scheduled report at the configured time.

Reads config from environment variables (persisted to .env via settings API):
    SENTINEL_REPORT_ENABLED  — "true" / "false"  (default: false)
    SENTINEL_REPORT_PERIOD   — "daily" / "weekly" (default: daily)
    SENTINEL_REPORT_TIME     — "HH:MM" UTC        (default: 08:00)
    SENTINEL_REPORT_DAY      — 0-6  Mon=0         (weekly only, default: 0)
"""

import logging
import os
import threading

logger = logging.getLogger(__name__)

_stop_event = threading.Event()


def _cfg():
    return {
        "enabled": os.environ.get("SENTINEL_REPORT_ENABLED", "false").lower() == "true",
        "period":  os.environ.get("SENTINEL_REPORT_PERIOD", "daily"),
        "time":    os.environ.get("SENTINEL_REPORT_TIME", "08:00"),
        "day":     int(os.environ.get("SENTINEL_REPORT_DAY", "0")),
    }


def _should_fire(cfg, now):
    try:
        h, m = map(int, cfg["time"].split(":"))
    except ValueError:
        return False
    if now.hour != h or now.minute != m:
        return False
    if cfg["period"] == "weekly":
        return now.weekday() == cfg["day"]
    return True


def _loop():
    from datetime import datetime, timezone
    logger.info("Report scheduler started.")
    last_fired_minute = -1

    while not _stop_event.is_set():
        cfg = _cfg()
        if cfg["enabled"]:
            now = datetime.now(timezone.utc)
            current_minute = now.hour * 60 + now.minute
            if _should_fire(cfg, now) and current_minute != last_fired_minute:
                last_fired_minute = current_minute
                logger.info(f"Scheduler firing {cfg['period']} report…")
                try:
                    from reporter import send_scheduled_report
                    send_scheduled_report(cfg["period"])
                except Exception as e:
                    logger.error(f"Scheduler error: {e}")
        _stop_event.wait(30)

    logger.info("Report scheduler stopped.")


def start():
    _stop_event.clear()
    t = threading.Thread(target=_loop, name="report-scheduler", daemon=True)
    t.start()


def stop():
    _stop_event.set()
