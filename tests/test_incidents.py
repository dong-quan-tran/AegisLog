# tests/test_incidents.py

import math

from aegislog.incidents import (
    _compute_severity,
    _compute_confidence,
    _compute_priority,
    _classify_attack_pattern,
    group_sessions_to_incidents,
)
from aegislog.features.sessions import Session

import pandas as pd


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


def test_compute_severity_bruteforce_high():
    # high anomaly, lots of failures, high fail ratio → high
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
    priority, score, reason = _compute_priority(
        severity="high",
        confidence="high",
    )
    assert priority in {"high", "critical"}
    assert isinstance(score, int)
    assert "severity=high" in reason
    assert "confidence=high" in reason


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


def test_group_sessions_to_incidents_ip_centric_spray():
    # Two sessions from same IP over a short window, many users → 1 incident
    from datetime import datetime, timedelta

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

    # IP-centric grouping
    assert inc.ip == "1.2.3.4"
    assert set(inc.targeted_users) == {"user1", "user2"}
    assert inc.auth_failed == 300
    assert inc.auth_success == 0

    # Pattern + priority should be populated
    assert inc.attack_pattern in {"password_spray", "brute_force"}
    assert isinstance(inc.priority_score, int)
    assert inc.priority in {"low", "medium", "high", "critical"}


def test_group_sessions_to_incidents_possible_compromise():
    from datetime import datetime, timedelta

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