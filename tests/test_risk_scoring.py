"""
tests/test_risk_scoring.py

Unit tests for risk_scoring.py — alert/incident scoring and severity bands.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

import pytest
from risk_scoring import score_alert, score_incident, score_to_severity


# ── Helpers ────────────────────────────────────────────────────────────────────

def make_alert(rule_name="brute_force_ssh", risk_score=50, anomaly_level=None):
    return {
        "rule_name":     rule_name,
        "risk_score":    risk_score,
        "anomaly_level": anomaly_level,
    }


def make_incident(rules_triggered, alert_scores, anomaly_level=None):
    # Pad rules if fewer rules than scores (repeat last rule)
    rules_padded = list(rules_triggered)
    while len(rules_padded) < len(alert_scores):
        rules_padded.append(rules_triggered[-1])
    alerts = [{"risk_score": s, "rule_name": r} for s, r in zip(alert_scores, rules_padded)]
    return {
        "alerts":          alerts,
        "rules_triggered": list(rules_triggered),
        "anomaly_level":   anomaly_level,
    }


# ── score_to_severity ──────────────────────────────────────────────────────────

def test_severity_low():
    assert score_to_severity(0)  == "low"
    assert score_to_severity(20) == "low"
    assert score_to_severity(29) == "low"

def test_severity_medium():
    assert score_to_severity(30) == "medium"
    assert score_to_severity(45) == "medium"
    assert score_to_severity(59) == "medium"

def test_severity_high():
    assert score_to_severity(60) == "high"
    assert score_to_severity(70) == "high"
    assert score_to_severity(79) == "high"

def test_severity_critical():
    assert score_to_severity(80)  == "critical"
    assert score_to_severity(95)  == "critical"
    assert score_to_severity(100) == "critical"


# ── score_alert — base only ────────────────────────────────────────────────────

def test_alert_base_score_no_bonuses():
    alert = make_alert(risk_score=50, anomaly_level=None)
    result = score_alert(alert)
    assert result["risk_score"] == 50

def test_alert_anomaly_high_adds_20():
    alert = make_alert(risk_score=50, anomaly_level="high")
    result = score_alert(alert)
    assert result["risk_score"] == 70

def test_alert_anomaly_medium_adds_10():
    alert = make_alert(risk_score=50, anomaly_level="medium")
    result = score_alert(alert)
    assert result["risk_score"] == 60

def test_alert_time_rule_adds_10():
    alert = make_alert(rule_name="suspicious_login_time", risk_score=45, anomaly_level=None)
    result = score_alert(alert)
    assert result["risk_score"] == 55

def test_alert_time_rule_plus_anomaly():
    alert = make_alert(rule_name="suspicious_login_time", risk_score=45, anomaly_level="high")
    result = score_alert(alert)
    assert result["risk_score"] == 75

def test_alert_score_capped_at_100():
    alert = make_alert(risk_score=95, anomaly_level="high")
    result = score_alert(alert)
    assert result["risk_score"] == 100

def test_alert_score_minimum_zero():
    alert = make_alert(risk_score=0, anomaly_level=None)
    result = score_alert(alert)
    assert result["risk_score"] == 0


# ── score_alert — output fields ────────────────────────────────────────────────

def test_alert_severity_set():
    alert = make_alert(risk_score=70, anomaly_level=None)
    result = score_alert(alert)
    assert result["severity"] == "high"

def test_alert_score_breakdown_present():
    alert = make_alert(risk_score=50, anomaly_level="high")
    result = score_alert(alert)
    bd = result["score_breakdown"]
    assert "base_score"    in bd
    assert "time_bonus"    in bd
    assert "anomaly_bonus" in bd
    assert "total"         in bd

def test_alert_breakdown_values_correct():
    alert = make_alert(rule_name="suspicious_login_time", risk_score=45, anomaly_level="high")
    result = score_alert(alert)
    bd = result["score_breakdown"]
    assert bd["base_score"]    == 45
    assert bd["time_bonus"]    == 10
    assert bd["anomaly_bonus"] == 20
    assert bd["total"]         == 75


# ── score_incident — base ──────────────────────────────────────────────────────

def test_incident_base_is_max_alert_score():
    incident = make_incident(
        rules_triggered=["brute_force_ssh"],
        alert_scores=[40, 60, 30],
        anomaly_level=None,
    )
    result = score_incident(incident)
    assert result["score_breakdown"]["base_score"] == 60

def test_incident_no_bonuses():
    incident = make_incident(
        rules_triggered=["brute_force_ssh"],
        alert_scores=[50],
        anomaly_level=None,
    )
    result = score_incident(incident)
    assert result["risk_score"] == 50


# ── score_incident — correlation bonus ────────────────────────────────────────

def test_incident_two_categories_adds_15():
    incident = make_incident(
        rules_triggered=["brute_force_ssh", "sensitive_file_access"],
        alert_scores=[50, 45],
        anomaly_level=None,
    )
    result = score_incident(incident)
    assert result["score_breakdown"]["correlation_bonus"] == 15
    assert result["risk_score"] == 65

def test_incident_three_categories_adds_25():
    incident = make_incident(
        rules_triggered=["brute_force_ssh", "sudo_after_suspicious_login", "sensitive_file_access"],
        alert_scores=[50, 45, 45],
        anomaly_level=None,
    )
    result = score_incident(incident)
    assert result["score_breakdown"]["correlation_bonus"] == 25

def test_incident_one_category_no_correlation_bonus():
    incident = make_incident(
        rules_triggered=["brute_force_ssh"],
        alert_scores=[50],
        anomaly_level=None,
    )
    result = score_incident(incident)
    assert result["score_breakdown"]["correlation_bonus"] == 0


# ── score_incident — anomaly bonus ────────────────────────────────────────────

def test_incident_anomaly_high_adds_20():
    incident = make_incident(
        rules_triggered=["brute_force_ssh"],
        alert_scores=[50],
        anomaly_level="high",
    )
    result = score_incident(incident)
    assert result["score_breakdown"]["anomaly_bonus"] == 20
    assert result["risk_score"] == 70

def test_incident_anomaly_medium_adds_10():
    incident = make_incident(
        rules_triggered=["brute_force_ssh"],
        alert_scores=[50],
        anomaly_level="medium",
    )
    result = score_incident(incident)
    assert result["score_breakdown"]["anomaly_bonus"] == 10

def test_incident_score_capped_at_100():
    incident = make_incident(
        rules_triggered=["brute_force_ssh", "sudo_after_suspicious_login", "sensitive_file_access", "suspicious_login_time"],
        alert_scores=[90],
        anomaly_level="high",
    )
    result = score_incident(incident)
    assert result["risk_score"] == 100


# ── score_incident — full chain (real scenario) ────────────────────────────────

def test_full_chain_score_and_severity():
    """Simulates the sample data critical incident: base=45 +corr=15 +time=10 +anomaly=20 = 90 (critical)"""
    incident = make_incident(
        rules_triggered=["sensitive_file_access", "suspicious_login_time"],
        alert_scores=[45, 45],
        anomaly_level="high",
    )
    result = score_incident(incident)
    assert result["risk_score"] == 90
    assert result["severity"] == "critical"


# ── score_incident — output fields ────────────────────────────────────────────

def test_incident_has_severity():
    incident = make_incident(["brute_force_ssh"], [50], anomaly_level="high")
    result = score_incident(incident)
    assert "severity" in result

def test_incident_has_score_breakdown():
    incident = make_incident(["brute_force_ssh"], [50])
    result = score_incident(incident)
    bd = result["score_breakdown"]
    assert all(k in bd for k in ("base_score", "correlation_bonus", "time_bonus", "anomaly_bonus", "total"))

def test_incident_modifies_in_place():
    incident = make_incident(["brute_force_ssh"], [50])
    result = score_incident(incident)
    assert result is incident
