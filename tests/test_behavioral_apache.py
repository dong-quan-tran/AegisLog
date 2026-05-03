from datetime import datetime, timedelta
from types import SimpleNamespace

from aegislog.features.behavioral import sessions_to_features
from aegislog.features.sessions import Session


def _make_event(ts, status=None, path=None, level=None, message=None, source="apache_error"):
    return SimpleNamespace(
        timestamp=ts,
        status=status,
        path=path,
        user=None,
        ip=None,
        user_agent=level,
        message=message,
        raw="",
        source=source,
    )


def test_apache_features_basic_session():
    # Synthetic session: a short burst of 5xx + errors + rare messages
    start = datetime(2025, 1, 1, 2, 0, 0)
    events = []

    # 3 notice events
    for i in range(3):
        events.append(
            _make_event(
                start + timedelta(seconds=i),
                status=200,
                path="/health",
                level="notice",
                message="OK",
            )
        )

    # 5 error/5xx events in a tight burst (within 1 minute)
    for i in range(5):
        events.append(
            _make_event(
                start + timedelta(seconds=10 + i),
                status=500,
                path="/api/error",
                level="error",
                message=f"rare-error-{i}",  # all unique -> rare templates
            )
        )

    # Wrap into a Session
    s = Session(
        session_id="apache-test-session",
        ip="1.2.3.4",
        user=None,
        user_agent=None,
        start_time=start,
        end_time=start + timedelta(minutes=1),
        events=events,
        source_set={"apache_error"},
    )

    df = sessions_to_features([s])
    assert len(df) == 1
    row = df.iloc[0]

    # Basic sanity
    assert row["session_id"] == "apache-test-session"
    assert row["event_count"] == len(events)

    # We have 5xx statuses and a 5xx streak
    assert row["status_5xx"] == 5
    assert row["apache_5xx_streak_max"] >= 5

    # Error vs notice ratio: more errors than notices
    assert row["error_events"] == 5
    assert row["notice_events"] == 3
    assert row["apache_error_vs_notice_ratio"] > 1.0

    # Error burst and 5xx burst in a minute should be high
    assert row["apache_error_burst_max_per_minute"] >= 5
    assert row["apache_5xx_burst_max_per_minute"] >= 5

    # Distinct templates and rare template count
    assert row["apache_distinct_message_templates"] >= 6  # "OK" + 5 rares
    assert row["apache_rare_error_message_count"] == 5
    assert 0.0 < row["apache_rare_error_message_ratio"] <= 1.0

    # Rare hour: 2 AM is in the "rare" band (0–3)
    assert row["apache_rare_hour"] in (0, 1)