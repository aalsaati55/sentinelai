"""
anomaly_scoring.py

ML-based anomaly scoring using Isolation Forest (scikit-learn).

IMPORTANT: ML does NOT detect attacks.
It only scores how statistically *abnormal* a session is compared to
the observed baseline of all sessions in the current run.

Design
------
- Features are extracted from the session dict produced by aggregator.py.
- The model is trained on the full session corpus each run (unsupervised).
- Isolation Forest returns scores in range (-1 .. 0); we normalise to 0–1
  where higher = more anomalous.
- Anomaly levels are thresholded:
    < 0.40  → "low"
    0.40–0.69 → "medium"
    ≥ 0.70  → "high"
- The trained model is saved to models/isolation_forest.pkl so it can be
  loaded by the FastAPI backend for real-time scoring.

Input features (10):
    failed_login_count, success_login_count, invalid_user_count,
    sudo_count, custom_event_count, unique_usernames, event_rate,
    activity_hour, success_after_failures (0/1), privilege_after_login (0/1)
"""

import logging
import os
import pickle
from typing import Dict, Any, List, Tuple

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from config import MODELS_DIR

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────
MODEL_PATH   = os.path.join(MODELS_DIR, "isolation_forest.pkl")
SCALER_PATH  = os.path.join(MODELS_DIR, "scaler.pkl")

FEATURE_NAMES = [
    "failed_login_count",
    "success_login_count",
    "invalid_user_count",
    "sudo_count",
    "custom_event_count",
    "unique_usernames",
    "event_rate",
    "activity_hour",
    "success_after_failures",   # bool → 0/1
    "privilege_after_login",    # bool → 0/1
]

# Anomaly level thresholds (normalised score 0–1, higher = more anomalous)
_LEVEL_MEDIUM = 0.40
_LEVEL_HIGH   = 0.70

# Isolation Forest config
_IF_CONTAMINATION = 0.1   # expect ~10% of sessions to be anomalous
_IF_N_ESTIMATORS  = 100
_IF_RANDOM_STATE  = 42


# ──────────────────────────────────────────────
# Feature extraction
# ──────────────────────────────────────────────

def _extract_features(session: Dict[str, Any]) -> List[float]:
    """Extract the 10-feature vector from a session dict."""
    return [
        float(session.get("failed_login_count",  0)),
        float(session.get("success_login_count", 0)),
        float(session.get("invalid_user_count",  0)),
        float(session.get("sudo_count",          0)),
        float(session.get("custom_event_count",  0)),
        float(session.get("unique_usernames",     0)),
        float(session.get("event_rate",           0.0)),
        float(session.get("activity_hour",        0)),
        float(bool(session.get("success_after_failures", False))),
        float(bool(session.get("privilege_after_login",  False))),
    ]


def _normalise_score(raw: float) -> float:
    """
    Convert Isolation Forest raw score to 0–1 (higher = more anomalous).

    IF returns values in roughly (-0.5 .. 0.5):
        -0.5 = very anomalous
         0.5 = very normal
    We flip and scale to [0, 1].
    """
    return float(np.clip((-raw + 0.5), 0.0, 1.0))


def _level(normalised: float) -> str:
    if normalised >= _LEVEL_HIGH:
        return "high"
    if normalised >= _LEVEL_MEDIUM:
        return "medium"
    return "low"


# ──────────────────────────────────────────────
# Model training
# ──────────────────────────────────────────────

def train_model(
    sessions: List[Dict[str, Any]],
) -> Tuple["IsolationForest", "StandardScaler"]:
    """
    Train Isolation Forest on a corpus of sessions.

    Saves the model and scaler to models/ for reuse.
    Returns (model, scaler).
    """
    if len(sessions) < 2:
        logger.warning(
            "Only %d session(s) available — skipping Isolation Forest training. "
            "Need at least 2 samples.", len(sessions)
        )
        return None, None

    X = np.array([_extract_features(s) for s in sessions])

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=_IF_N_ESTIMATORS,
        contamination=_IF_CONTAMINATION,
        random_state=_IF_RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X_scaled)

    # Persist model + scaler
    os.makedirs(MODELS_DIR, exist_ok=True)
    with open(MODEL_PATH,  "wb") as f:
        pickle.dump(model,  f)
    with open(SCALER_PATH, "wb") as f:
        pickle.dump(scaler, f)

    logger.info(
        "Isolation Forest trained on %d sessions. "
        "Model saved to %s", len(sessions), MODEL_PATH
    )
    return model, scaler


def load_model() -> Tuple["IsolationForest | None", "StandardScaler | None"]:
    """Load a previously saved model and scaler. Returns (None, None) if not found."""
    if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
        return None, None
    try:
        with open(MODEL_PATH,  "rb") as f:
            model  = pickle.load(f)
        with open(SCALER_PATH, "rb") as f:
            scaler = pickle.load(f)
        logger.info("Isolation Forest model loaded from %s", MODEL_PATH)
        return model, scaler
    except Exception as e:
        logger.error("Failed to load model: %s", e)
        return None, None


# ──────────────────────────────────────────────
# Public API: score a single session
# ──────────────────────────────────────────────

def score_session(
    session: Dict[str, Any],
    model: "IsolationForest | None" = None,
    scaler: "StandardScaler | None" = None,
) -> Dict[str, Any]:
    """
    Score a single session dict.

    If model/scaler are not provided, attempts to load from disk.
    If no model is available, returns safe defaults (score=0.0, level="low").

    Returns:
        {
            "anomaly_score": float  — normalised 0–1
            "anomaly_level": str    — "low" / "medium" / "high"
        }
    """
    if model is None or scaler is None:
        model, scaler = load_model()

    if model is None:
        return {"anomaly_score": 0.0, "anomaly_level": "low"}

    features = np.array([_extract_features(session)])
    features_scaled = scaler.transform(features)
    raw = model.score_samples(features_scaled)[0]

    normalised = _normalise_score(raw)
    level      = _level(normalised)

    return {
        "anomaly_score": round(normalised, 4),
        "anomaly_level": level,
    }


# ──────────────────────────────────────────────
# Public API: score all sessions in a batch
# (trains a fresh model, then scores every session)
# ──────────────────────────────────────────────

def score_sessions(
    sessions: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Train Isolation Forest on `sessions`, then score each session.

    Mutates each session dict in-place with:
        session["anomaly_score"]  — float 0–1
        session["anomaly_level"]  — "low" / "medium" / "high"

    Also returns the list for chaining.
    """
    model, scaler = train_model(sessions)

    if model is None:
        for s in sessions:
            s["anomaly_score"] = 0.0
            s["anomaly_level"] = "low"
        return sessions

    X = np.array([_extract_features(s) for s in sessions])
    X_scaled = scaler.transform(X)
    raw_scores = model.score_samples(X_scaled)

    high_count   = 0
    medium_count = 0

    for session, raw in zip(sessions, raw_scores):
        normalised = _normalise_score(raw)
        level      = _level(normalised)
        session["anomaly_score"] = round(normalised, 4)
        session["anomaly_level"] = level
        if level == "high":
            high_count += 1
        elif level == "medium":
            medium_count += 1

    logger.info(
        "Anomaly scoring complete: %d high, %d medium, %d low out of %d sessions.",
        high_count, medium_count,
        len(sessions) - high_count - medium_count,
        len(sessions),
    )
    return sessions
