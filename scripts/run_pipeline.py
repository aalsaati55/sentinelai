"""
run_pipeline.py

End-to-end pipeline runner for SentinelAI.

Stages:
    1. Collect   — read all log files from data/logs/
    2. Parse     — parse each line into a normalized event dict
    3. Store     — bulk-insert events into SQLite
    4. Aggregate — group events into time-windowed sessions
    5. Detect    — run rule-based detection on each session
    6. Correlate — group related alerts into incidents
    7. Score     — apply risk scoring to alerts and incidents
    8. Store     — persist alerts and incidents to DB
    9. Summary   — print results

Usage:
    python scripts/run_pipeline.py
    python scripts/run_pipeline.py --reset   # clear DB before running
"""

import sys
import os
import argparse
import logging

# Make sure backend/ is on the path when run from project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from utils import setup_logging
from storage import (
    init_db, clear_all_data,
    insert_events_bulk, count_events,
    insert_alert, insert_incident, link_incident_events,
    count_alerts, count_incidents,
)
from collector import collect_all
from aggregator import aggregate_events
from anomaly_scoring import score_sessions
from detection import run_detection
from correlation import correlate_alerts
from risk_scoring import score_alert, score_incident

setup_logging(logging.INFO)
logger = logging.getLogger("pipeline")


def run(reset: bool = False) -> None:
    logger.info("=" * 60)
    logger.info("SentinelAI Pipeline — starting")
    logger.info("=" * 60)

    # ── 1. Init DB ──────────────────────────────────────────
    init_db()
    if reset:
        clear_all_data()
        logger.info("Database reset: all previous data cleared.")

    # ── 2. Collect + Parse ──────────────────────────────────
    logger.info("Stage 1/5 — Collecting and parsing log files...")
    events = collect_all()
    if not events:
        logger.warning("No events collected. Check that log files exist in data/logs/")
        return

    # ── 3. Store events ─────────────────────────────────────
    logger.info(f"Stage 2/6 — Storing {len(events)} events into database...")
    insert_events_bulk(events)
    logger.info(f"  Total events in DB: {count_events()}")

    # ── 4. Aggregate ────────────────────────────────────────
    logger.info("Stage 3/6 — Aggregating events into sessions...")
    sessions = aggregate_events(events)
    logger.info(f"  Sessions created: {len(sessions)}")

    # ── 5. Anomaly scoring (ML) ─────────────────────────────
    logger.info("Stage 4/6 — Running Isolation Forest anomaly scoring...")
    score_sessions(sessions)
    high_anomaly   = sum(1 for s in sessions if s.get("anomaly_level") == "high")
    medium_anomaly = sum(1 for s in sessions if s.get("anomaly_level") == "medium")
    logger.info(f"  Anomaly levels — high: {high_anomaly}, medium: {medium_anomaly}, "
                f"low: {len(sessions) - high_anomaly - medium_anomaly}")

    # ── 6. Detect ───────────────────────────────────────────
    logger.info("Stage 5/6 — Running detection rules...")
    raw_alerts = run_detection(sessions)
    logger.info(f"  Raw alerts fired: {len(raw_alerts)}")

    # Build a lookup: session_key → anomaly info for propagation into alerts
    session_anomaly = {
        s["session_key"]: {
            "anomaly_score": s.get("anomaly_score", 0.0),
            "anomaly_level": s.get("anomaly_level", "low"),
        }
        for s in sessions
    }

    # Propagate anomaly level into each alert, then score
    for alert in raw_alerts:
        key = alert.get("session_key", "")
        info = session_anomaly.get(key, {})
        alert["anomaly_score"] = info.get("anomaly_score", 0.0)
        alert["anomaly_level"] = info.get("anomaly_level", "low")
        score_alert(alert)

    # ── 7. Correlate ────────────────────────────────────────
    logger.info("Stage 6/6 — Correlating alerts into incidents...")
    incidents = correlate_alerts(raw_alerts)

    # Propagate highest anomaly level among contributing alerts to each incident
    for incident in incidents:
        levels = [a.get("anomaly_level", "low") for a in incident.get("alerts", [])]
        if "high" in levels:
            incident["anomaly_level"] = "high"
        elif "medium" in levels:
            incident["anomaly_level"] = "medium"
        else:
            incident["anomaly_level"] = "low"
        score_incident(incident)

    # ── 7. Store alerts + incidents ─────────────────────────
    logger.info("Storing alerts and incidents...")
    for alert in raw_alerts:
        insert_alert({
            "event_id":      None,
            "rule_name":     alert["rule_name"],
            "severity":      alert["severity"],
            "risk_score":    alert["risk_score"],
            "anomaly_score": alert.get("anomaly_score"),
            "anomaly_level": alert.get("anomaly_level"),
            "description":   alert["description"],
        })

    for incident in incidents:
        inc_id = insert_incident({
            "title":         incident["title"],
            "description":   incident["description"],
            "source_ip":     incident.get("source_ip"),
            "username":      incident.get("username"),
            "risk_score":    incident["risk_score"],
            "anomaly_level": incident.get("anomaly_level"),
            "status":        "open",
        })
        # Link all event IDs from contributing alerts to this incident
        event_ids = []
        for alert in incident.get("alerts", []):
            for e in alert.get("session", {}).get("events", []):
                if e.get("id"):
                    event_ids.append(e["id"])
        link_incident_events(inc_id, list(set(event_ids)))

    # ── 8. Summary ──────────────────────────────────────────
    logger.info("=" * 60)
    logger.info("Pipeline complete — Summary")
    logger.info("=" * 60)
    logger.info(f"  Events collected  : {len(events)}")
    logger.info(f"  Sessions created  : {len(sessions)}")
    logger.info(f"  Alerts fired      : {len(raw_alerts)}")
    logger.info(f"  Incidents created : {len(incidents)}")
    logger.info(f"  Total alerts in DB: {count_alerts()}")
    logger.info("")
    logger.info("  ALERTS:")
    for a in sorted(raw_alerts, key=lambda x: x["risk_score"], reverse=True):
        logger.info(
            f"    [{a['severity'].upper():8s}] score={a['risk_score']:3d} | "
            f"{a['rule_name']:35s} | {a.get('source_ip','N/A')} / {a.get('username','N/A')}"
        )
    logger.info("")
    logger.info("  INCIDENTS:")
    for i in sorted(incidents, key=lambda x: x["risk_score"], reverse=True):
        rules = ", ".join(i["rules_triggered"])
        logger.info(
            f"    [{i.get('severity','?').upper():8s}] score={i['risk_score']:3d} | "
            f"{i['title'][:50]}"
        )
        logger.info(f"      Rules: {rules}")
        breakdown = i.get("score_breakdown", {})
        logger.info(
            f"      Score breakdown: base={breakdown.get('base_score',0)} "
            f"corr=+{breakdown.get('correlation_bonus',0)} "
            f"time=+{breakdown.get('time_bonus',0)} "
            f"anomaly=+{breakdown.get('anomaly_bonus',0)}"
        )
    logger.info("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SentinelAI pipeline runner")
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Clear all database data before running the pipeline",
    )
    args = parser.parse_args()
    run(reset=args.reset)
