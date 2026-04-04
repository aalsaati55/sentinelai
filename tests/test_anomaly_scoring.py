"""
tests/test_anomaly_scoring.py

Unit tests for anomaly_scoring.py — feature extraction, normalisation,
level thresholding, and batch scoring behaviour.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

import pytest
import numpy as np
from anomaly_scoring import (
    _extract_features,
    _normalise_score,
    _level,
    score_sessions,
    train_model,
    FEATURE_NAMES,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def make_session(**kwargs):
    defaults = {
        "failed_login_count":  0,
        "success_login_count": 0,
        "invalid_user_count":  0,
        "sudo_count":          0,
        "custom_event_count":  0,
        "unique_usernames":    1,
        "event_rate":          1.0,
        "activity_hour":       10,
        "success_after_failures": False,
        "privilege_after_login":  False,
    }
    defaults.update(kwargs)
    return defaults


def normal_sessions(n=15):
    """Generate n normal-looking sessions for training."""
    return [make_session(
        failed_login_count=0,
        success_login_count=1,
        activity_hour=9 + (i % 8),
        event_rate=1.0,
        unique_usernames=1,
    ) for i in range(n)]


# ── _extract_features ──────────────────────────────────────────────────────────

def test_feature_vector_length():
    session = make_session()
    features = _extract_features(session)
    assert len(features) == len(FEATURE_NAMES)

def test_feature_vector_all_floats():
    session = make_session()
    features = _extract_features(session)
    assert all(isinstance(f, float) for f in features)

def test_feature_failed_login_count():
    session = make_session(failed_login_count=99)
    features = _extract_features(session)
    assert features[0] == 99.0

def test_feature_success_after_failures_bool_true():
    session = make_session(success_after_failures=True)
    features = _extract_features(session)
    assert features[8] == 1.0

def test_feature_success_after_failures_bool_false():
    session = make_session(success_after_failures=False)
    features = _extract_features(session)
    assert features[8] == 0.0

def test_feature_privilege_after_login_bool():
    session = make_session(privilege_after_login=True)
    features = _extract_features(session)
    assert features[9] == 1.0

def test_feature_missing_keys_default_to_zero():
    session = {}
    features = _extract_features(session)
    assert features == [0.0] * len(FEATURE_NAMES)

def test_feature_activity_hour():
    session = make_session(activity_hour=23)
    features = _extract_features(session)
    assert features[7] == 23.0


# ── _normalise_score ───────────────────────────────────────────────────────────

def test_normalise_most_anomalous():
    """Raw score of -0.5 → normalised 1.0 (max anomaly)."""
    assert _normalise_score(-0.5) == pytest.approx(1.0)

def test_normalise_most_normal():
    """Raw score of 0.5 → normalised 0.0 (not anomalous)."""
    assert _normalise_score(0.5) == pytest.approx(0.0)

def test_normalise_midpoint():
    """Raw score of 0.0 → normalised 0.5."""
    assert _normalise_score(0.0) == pytest.approx(0.5)

def test_normalise_clamped_above_1():
    """Scores more extreme than -0.5 are clamped to 1.0."""
    assert _normalise_score(-2.0) == pytest.approx(1.0)

def test_normalise_clamped_below_0():
    """Scores more extreme than 0.5 are clamped to 0.0."""
    assert _normalise_score(2.0) == pytest.approx(0.0)


# ── _level ─────────────────────────────────────────────────────────────────────

def test_level_low_below_threshold():
    assert _level(0.0)  == "low"
    assert _level(0.20) == "low"
    assert _level(0.39) == "low"

def test_level_medium_at_threshold():
    assert _level(0.40) == "medium"
    assert _level(0.55) == "medium"
    assert _level(0.69) == "medium"

def test_level_high_at_threshold():
    assert _level(0.70) == "high"
    assert _level(0.85) == "high"
    assert _level(1.0)  == "high"


# ── score_sessions — structure ─────────────────────────────────────────────────

def test_score_sessions_returns_same_list():
    sessions = normal_sessions(10)
    result = score_sessions(sessions)
    assert result is sessions

def test_score_sessions_adds_anomaly_score():
    sessions = normal_sessions(10)
    score_sessions(sessions)
    for s in sessions:
        assert "anomaly_score" in s

def test_score_sessions_adds_anomaly_level():
    sessions = normal_sessions(10)
    score_sessions(sessions)
    for s in sessions:
        assert "anomaly_level" in s

def test_score_sessions_anomaly_score_in_range():
    sessions = normal_sessions(10)
    score_sessions(sessions)
    for s in sessions:
        assert 0.0 <= s["anomaly_score"] <= 1.0

def test_score_sessions_anomaly_level_valid():
    sessions = normal_sessions(10)
    score_sessions(sessions)
    for s in sessions:
        assert s["anomaly_level"] in ("low", "medium", "high")


# ── score_sessions — single session fallback ───────────────────────────────────

def test_score_sessions_single_session_returns_defaults():
    """With only 1 session, model can't train — should return safe defaults."""
    sessions = [make_session()]
    result = score_sessions(sessions)
    assert result[0]["anomaly_score"] == 0.0
    assert result[0]["anomaly_level"] == "low"

def test_score_sessions_empty_returns_empty():
    result = score_sessions([])
    assert result == []


# ── score_sessions — attack session scores higher than normal ──────────────────

def test_attack_session_scores_higher_than_normal():
    """
    A session with 500 failed logins + success + privilege escalation should
    score more anomalous than a clean session, after training on mostly normal data.
    """
    sessions = normal_sessions(20)
    attack = make_session(
        failed_login_count=500,
        success_login_count=1,
        success_after_failures=True,
        privilege_after_login=True,
        sudo_count=10,
        activity_hour=3,
        event_rate=50.0,
    )
    sessions.append(attack)
    score_sessions(sessions)

    normal_avg = sum(s["anomaly_score"] for s in sessions[:-1]) / len(sessions[:-1])
    assert sessions[-1]["anomaly_score"] > normal_avg


# ── train_model ────────────────────────────────────────────────────────────────

def test_train_model_returns_model_and_scaler():
    sessions = normal_sessions(10)
    model, scaler = train_model(sessions)
    assert model is not None
    assert scaler is not None

def test_train_model_single_session_returns_none():
    model, scaler = train_model([make_session()])
    assert model is None
    assert scaler is None

def test_train_model_zero_sessions_returns_none():
    model, scaler = train_model([])
    assert model is None
    assert scaler is None

def test_trained_model_can_score_samples():
    sessions = normal_sessions(10)
    model, scaler = train_model(sessions)
    import numpy as np
    features = np.array([_extract_features(make_session())])
    scaled   = scaler.transform(features)
    score    = model.score_samples(scaled)
    assert len(score) == 1
    assert isinstance(score[0], float)
