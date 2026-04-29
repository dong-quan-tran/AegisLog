# tests/test_incidents.py

from datetime import datetime, timedelta

import pandas as pd

from aegislog.features.sessions import Session
from aegislog.incidents import (
    _classify_attack_pattern,
    _compute_confidence,
    _confidence_reason,
    _compute_priority,
    _compute_severity,
    _severity_reason,
    group_sessions_to_incidents,
)


def make_session(session_id, ip, user, start, end):
    return Session(
        session_id=session_id,
        ip=ip,
        user=user,
        start_time=start,
        end_time=end,
        user_agent=None,
        events=[],
        source_set={ip} if ip else set(),
    )


# --- severity / confidence / priority -------------------------------------------------------------


def test_compute_severity_bruteforce_high():
    severity = _compute_severity(
        avg_anomaly_score=0.30,
        auth_failed=500,
        auth_fail_ratio=0.96,
        has_success_after_failures=False,
    )
    assert severity == "high"


def test_compute_severity_low_noise():
    severity = _compute_severity(
        avg_anomaly_score=0.05,
        auth_failed=5,
        auth_fail_ratio=0.5,
        has_success_after_failures=False,
    )
    assert severity == "low"


def test_compute_confidence_high_with_repeated_activity():
    confidence = _compute_confidence(
        avg_anomaly_score=0.32,
        auth_failed=60,
        auth_fail_ratio=0.9,
        session_count=3,
        has_success_after_failures=False,
    )
    assert confidence == "high"


def test_compute_confidence_low_signal():
    confidence = _compute_confidence(
        avg_anomaly_score=0.05,
        auth_failed=3,
        auth_fail_ratio=0.3,
        session_count=1,
        has_success_after_failures=False,
    )
    assert confidence == "low"


def test_compute_priority_from_severity_and_confidence():
    # SEVERITY_TO_SCORE["high"] = 80, CONFIDENCE_TO_SCORE["high"] = 85
    # priority_score = round(80 * 85 / 100) = 68 => "critical"
    priority, score, reason = _compute_priority(
        severity="high",
        confidence="high",
    )
    assert priority == "critical"
    assert score == 68
    assert "severity=high" in reason
    assert "confidence=high" in reason


def test_compute_priority_other_combinations():
    # medium + medium -> round(50 * 60 / 100) = 30 -> "medium"
    priority, score, _ = _compute_priority(
        severity="medium",
        confidence="medium",
    )
    assert priority == "medium"
    assert score == 30

    # low + low -> round(25 * 30 / 100) = 8 -> "low"
    priority2, score2, _ = _compute_priority(
        severity="low",
        confidence="low",
    )
    assert priority2 == "low"
    assert score2 == 8


def test_extreme_ssh_bruteforce_gets_high_severity_and_confidence():
    """
    Very large failed-auth volume with intense automation indicators
    should be classified as high severity and high confidence.
    """
    avg_anomaly_score = 0.3
    auth_failed = 5000
    auth_fail_ratio = 0.99
    session_count = 3
    has_success_after_failures = False
    auth_failed_streak_max = 2000
    auth_burst_max_per_minute = 800

    severity = _compute_severity(
        avg_anomaly_score=avg_anomaly_score,
        auth_failed=auth_failed,
        auth_fail_ratio=auth_fail_ratio,
        has_success_after_failures=has_success_after_failures,
        auth_failed_streak_max=auth_failed_streak_max,
        auth_burst_max_per_minute=auth_burst_max_per_minute,
    )
    severity_reason = _severity_reason(
        avg_anomaly_score=avg_anomaly_score,
        auth_failed=auth_failed,
        auth_fail_ratio=auth_fail_ratio,
        has_success_after_failures=has_success_after_failures,
        auth_failed_streak_max=auth_failed_streak_max,
        auth_burst_max_per_minute=auth_burst_max_per_minute,
    )

    confidence = _compute_confidence(
        avg_anomaly_score=avg_anomaly_score,
        auth_failed=auth_failed,
        auth_fail_ratio=auth_fail_ratio,
        session_count=session_count,
        has_success_after_failures=has_success_after_failures,
        auth_failed_streak_max=auth_failed_streak_max,
        auth_burst_max_per_minute=auth_burst_max_per_minute,
    )
    confidence_reason = _confidence_reason(
        avg_anomaly_score=avg_anomaly_score,
        auth_failed=auth_failed,
        auth_fail_ratio=auth_fail_ratio,
        session_count=session_count,
        has_success_after_failures=has_success_after_failures,
        auth_failed_streak_max=auth_failed_streak_max,
        auth_burst_max_per_minute=auth_burst_max_per_minute,
    )

    assert severity == "high"
    assert "extremely high failed-auth volume" in severity_reason

    assert confidence == "high"
    assert (
        "very long consecutive failed-auth streak" in confidence_reason
        or "very high SSH event rate" in confidence_reason
    )


# --- attack pattern -------------------------------------------------------------------------------


def test_classify_attack_pattern_bruteforce():
    pattern, reason = _classify_attack_pattern(
        auth_failed=500,
        auth_success=0,
        auth_fail_ratio=0.98,
        targeted_users=["root", "root", "root"],
        has_success_after_failures=False,
    )
    assert pattern == "brute_force"
    assert "high-volume failed SSH authentication attempts" in reason


def test_classify_attack_pattern_password_spray():
    pattern, reason = _classify_attack_pattern(
        auth_failed=300,
        auth_success=0,
        auth_fail_ratio=0.97,
        targeted_users=["user1", "user2", "user3", "user4", "user5", "user6"],
        has_success_after_failures=False,
    )
    assert pattern == "password_spray"
    assert "distinct user(s)" in reason


def test_classify_attack_pattern_possible_compromise():
    pattern, reason = _classify_attack_pattern(
        auth_failed=30,
        auth_success=2,
        auth_fail_ratio=0.6,
        targeted_users=["alice"],
        has_success_after_failures=True,
    )
    assert pattern == "possible_compromise"
    assert "successful login(s)" in reason


# --- grouping -------------------------------------------------------------------------------------


def test_group_sessions_to_incidents_ip_centric_two_users_spray_like():
    # Two sessions from same IP over a short window, many users → 1 incident
    base = datetime(2025, 1, 1, 0, 0, 0)
    sessions = [
        make_session("s1", "1.2.3.4", "user1", base, base + timedelta(minutes=5)),
        make_session("s2", "1.2.3.4", "user2", base + timedelta(minutes=10), base + timedelta(minutes=15)),
    ]

    scores_df = pd.DataFrame(
        [
            {
                "session_id": "s1",
                "ip": "1.2.3.4",
                "user": "user1",
                "event_count": 200,
                "anomaly_score": 0.3,
                "auth_failed": 150,
                "auth_success": 0,
            },
            {
                "session_id": "s2",
                "ip": "1.2.3.4",
                "user": "user2",
                "event_count": 200,
                "anomaly_score": 0.28,
                "auth_failed": 150,
                "auth_success": 0,
            },
        ]
    )

    incidents = group_sessions_to_incidents(
        sessions,
        scores_df,
        min_sessions=1,
        merge_window_minutes=60,
    )

    assert len(incidents) == 1
    inc = incidents[0]

    assert inc.ip == "1.2.3.4"
    assert set(inc.targeted_users) == {"user1", "user2"}
    assert inc.auth_failed == 300
    assert inc.auth_success == 0

    assert inc.attack_pattern in {"password_spray", "brute_force"}
    assert isinstance(inc.priority_score, int)
    assert inc.priority in {"low", "medium", "high", "critical"}


def test_group_sessions_to_incidents_possible_compromise():
    base = datetime(2025, 1, 1, 0, 0, 0)
    sessions = [
        make_session("s1", "5.6.7.8", "alice", base, base + timedelta(minutes=5)),
        make_session("s2", "5.6.7.8", "alice", base + timedelta(minutes=10), base + timedelta(minutes=12)),
    ]

    scores_df = pd.DataFrame(
        [
            {
                "session_id": "s1",
                "ip": "5.6.7.8",
                "user": "alice",
                "event_count": 100,
                "anomaly_score": 0.30,
                "auth_failed": 40,
                "auth_success": 0,
            },
            {
                "session_id": "s2",
                "ip": "5.6.7.8",
                "user": "alice",
                "event_count": 20,
                "anomaly_score": 0.25,
                "auth_failed": 5,
                "auth_success": 1,
            },
        ]
    )

    incidents = group_sessions_to_incidents(sessions, scores_df)

    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.attack_pattern == "possible_compromise"
    assert inc.auth_success == 1
    assert inc.has_success_after_failures is True


def test_group_sessions_to_incidents_ip_centric_password_spray_many_users():
    base = datetime(2025, 1, 1, 0, 0, 0)
    sessions = [
        make_session("s1", "1.2.3.4", "user1", base, base + timedelta(minutes=5)),
        make_session("s2", "1.2.3.4", "user2", base + timedelta(minutes=10), base + timedelta(minutes=15)),
        make_session("s3", "1.2.3.4", "user3", base + timedelta(minutes=20), base + timedelta(minutes=25)),
        make_session("s4", "1.2.3.4", "user4", base + timedelta(minutes=30), base + timedelta(minutes=35)),
        make_session("s5", "1.2.3.4", "user5", base + timedelta(minutes=40), base + timedelta(minutes=45)),
    ]

    scores_df = pd.DataFrame(
        [
            {"session_id": "s1", "ip": "1.2.3.4", "user": "user1", "event_count": 100, "anomaly_score": 0.30, "auth_failed": 80, "auth_success": 0},
            {"session_id": "s2", "ip": "1.2.3.4", "user": "user2", "event_count": 100, "anomaly_score": 0.29, "auth_failed": 80, "auth_success": 0},
            {"session_id": "s3", "ip": "1.2.3.4", "user": "user3", "event_count": 100, "anomaly_score": 0.31, "auth_failed": 80, "auth_success": 0},
            {"session_id": "s4", "ip": "1.2.3.4", "user": "user4", "event_count": 100, "anomaly_score": 0.28, "auth_failed": 80, "auth_success": 0},
            {"session_id": "s5", "ip": "1.2.3.4", "user": "user5", "event_count": 100, "anomaly_score": 0.30, "auth_failed": 80, "auth_success": 0},
        ]
    )

    incidents = group_sessions_to_incidents(sessions, scores_df)

    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.attack_pattern == "password_spray"
    assert set(inc.targeted_users) == {"user1", "user2", "user3", "user4", "user5"}
    assert inc.primary_user in inc.targeted_users