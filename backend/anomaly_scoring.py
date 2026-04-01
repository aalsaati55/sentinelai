"""
anomaly_scoring.py

ML-based anomaly scoring using Isolation Forest (scikit-learn).

IMPORTANT: ML does NOT detect attacks.
It only scores how statistically abnormal a session/incident is.

Input features per session:
    - failed_login_count
    - success_login_count
    - invalid_user_count
    - sudo_count
    - custom_event_count
    - unique_usernames
    - event_rate
    - activity_hour
    - success_after_failures
    - privilege_after_login

Output:
    - anomaly_score  (float, raw Isolation Forest score)
    - anomaly_level  ("low" / "medium" / "high")

Placeholder — full implementation in Week 4.
"""

from typing import Dict, Any


def score_session(session: Dict[str, Any]) -> Dict[str, Any]:
    """
    Score a session using Isolation Forest.
    Returns dict with anomaly_score and anomaly_level.

    TODO: Implement in Week 4.
    """
    return {"anomaly_score": 0.0, "anomaly_level": "low"}
