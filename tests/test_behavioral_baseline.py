from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from aegislog.features.behavioral import sessions_to_features
from aegislog.features.sessions import Session


def _make_event(ts, status=200, user=None, ip=None, source="ssh_auth"):
    return SimpleNamespace(
        timestamp=ts,
        status=status,
        path=None,
        user=user,
        ip=ip,
        user_agent=None,
        message=None,
        raw="",
        source=source,
    )


def _make_session(session_id, start, ip, user, event_count, source="ssh_auth"):
    events = [
        _make_event(
            start + timedelta(seconds=i),
            status=200 if i % 2 == 0 else 401,
            user=user,
            ip=ip,
            source=source,
        )
        for i in range(event_count)
    ]
    return Session(
        session_id=session_id,
        ip=ip,
        user=user,
        user_agent=None,
        start_time=start,
        end_time=start + timedelta(seconds=max(event_count - 1, 0)),
        events=events,
        source_set={source},
    )


def test_baseline_and_rare_seen_features_for_ip_and_user():
    start = datetime(2025, 1, 1, 12, 0, 0)

    sessions = [
        _make_session("s1", start, "1.1.1.1", "alice", 2),
        _make_session("s2", start + timedelta(minutes=5), "1.1.1.1", "alice", 4),
        _make_session("s3", start + timedelta(minutes=10), "1.1.1.1", "alice", 8),
        _make_session("s4", start + timedelta(minutes=15), "2.2.2.2", "bob", 3),
    ]

    df = sessions_to_features(sessions).set_index("session_id")

    # First-seen flags
    assert df.loc["s1", "first_seen_ip_flag"] == 1
    assert df.loc["s1", "first_seen_user_flag"] == 1
    assert df.loc["s2", "first_seen_ip_flag"] == 0
    assert df.loc["s2", "first_seen_user_flag"] == 0

    # Rare-seen flags:
    # 1.1.1.1 / alice appear in 3 sessions, so with threshold < 3 they are not rare.
    # 2.2.2.2 / bob appear in only 1 session, so they are rare.
    assert df.loc["s1", "rare_seen_ip_flag"] == 0
    assert df.loc["s1", "rare_seen_user_flag"] == 0
    assert df.loc["s4", "rare_seen_ip_flag"] == 1
    assert df.loc["s4", "rare_seen_user_flag"] == 1

    # Baseline events/session for IP 1.1.1.1 and user alice:
    # (2 + 4 + 8) / 3 = 14 / 3
    expected_baseline = 14 / 3

    assert df.loc["s1", "ip_events_per_session"] == pytest.approx(expected_baseline)
    assert df.loc["s2", "ip_events_per_session"] == pytest.approx(expected_baseline)
    assert df.loc["s3", "ip_events_per_session"] == pytest.approx(expected_baseline)

    assert df.loc["s1", "user_events_per_session"] == pytest.approx(expected_baseline)
    assert df.loc["s2", "user_events_per_session"] == pytest.approx(expected_baseline)
    assert df.loc["s3", "user_events_per_session"] == pytest.approx(expected_baseline)

    # Deviations = current event_count - baseline
    assert df.loc["s1", "ip_events_per_session_deviation"] == pytest.approx(2 - expected_baseline)
    assert df.loc["s2", "ip_events_per_session_deviation"] == pytest.approx(4 - expected_baseline)
    assert df.loc["s3", "ip_events_per_session_deviation"] == pytest.approx(8 - expected_baseline)

    assert df.loc["s1", "user_events_per_session_deviation"] == pytest.approx(2 - expected_baseline)
    assert df.loc["s2", "user_events_per_session_deviation"] == pytest.approx(4 - expected_baseline)
    assert df.loc["s3", "user_events_per_session_deviation"] == pytest.approx(8 - expected_baseline)

    # Single-session identity baseline should equal its own event count, deviation 0
    assert df.loc["s4", "ip_events_per_session"] == pytest.approx(3.0)
    assert df.loc["s4", "user_events_per_session"] == pytest.approx(3.0)
    assert df.loc["s4", "ip_events_per_session_deviation"] == pytest.approx(0.0)
    assert df.loc["s4", "user_events_per_session_deviation"] == pytest.approx(0.0)