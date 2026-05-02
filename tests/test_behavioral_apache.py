from datetime import datetime, timedelta

from aegislog.features.behavioral import sessions_to_features
from aegislog.features.sessions import Session


class DummyEvent:
    def __init__(self, timestamp, status=None, path=None, message=None):
        self.timestamp = timestamp
        self.status = status
        self.path = path
        self.message = message
        self.user = None
        self.ip = None
        self.user_agent = "error"


def make_session(session_id, start, events):
    return Session(
        session_id=session_id,
        ip=None,
        user=None,
        start_time=start,
        end_time=events[-1].timestamp if events else start,
        user_agent=None,
        events=events,
        source_set=set(),
    )


def test_sessions_to_features_adds_apache_feature_columns():
    base = datetime(2025, 1, 1, 1, 0, 0)

    session1_events = [
        DummyEvent(base + timedelta(seconds=0), status=500, path="/api/a", message="db error"),
        DummyEvent(base + timedelta(seconds=5), status=500, path="/api/a", message="db error"),
        DummyEvent(base + timedelta(seconds=10), status=404, path="/missing", message="not found"),
    ]
    session2_events = [
        DummyEvent(base + timedelta(minutes=10), status=200, path="/home", message="ok"),
        DummyEvent(base + timedelta(minutes=11), status=200, path="/home", message="ok"),
    ]

    sessions = [
        make_session("apache-1", base, session1_events),
        make_session("apache-2", base + timedelta(minutes=10), session2_events),
    ]

    df = sessions_to_features(sessions)

    required_cols = {
        "apache_5xx_streak_max",
        "apache_404_burst_max_per_minute",
        "apache_5xx_burst_max_per_minute",
        "apache_distinct_paths",
        "apache_rare_path_ratio",
        "apache_rare_error_message_ratio",
        "apache_rare_hour",
    }

    missing = required_cols - set(df.columns)
    assert not missing, f"Missing Apache feature columns: {sorted(missing)}"


def test_sessions_to_features_computes_apache_bursts_and_streaks():
    base = datetime(2025, 1, 1, 2, 0, 0)

    events = [
        DummyEvent(base + timedelta(seconds=0), status=500, path="/api/a", message="db error"),
        DummyEvent(base + timedelta(seconds=10), status=500, path="/api/b", message="db error"),
        DummyEvent(base + timedelta(seconds=20), status=503, path="/api/c", message="upstream timeout"),
        DummyEvent(base + timedelta(seconds=30), status=404, path="/missing-1", message="not found"),
        DummyEvent(base + timedelta(seconds=40), status=404, path="/missing-2", message="not found"),
    ]

    session = make_session("apache-burst", base, events)
    df = sessions_to_features([session])
    row = df.iloc[0]

    assert row["apache_5xx_streak_max"] == 3
    assert row["apache_5xx_burst_max_per_minute"] == 3
    assert row["apache_404_burst_max_per_minute"] == 2
    assert row["apache_distinct_paths"] == 5
    assert row["apache_rare_hour"] == 1


def test_sessions_to_features_computes_apache_rarity_ratios_across_sessions():
    base = datetime(2025, 1, 1, 10, 0, 0)

    # Session 1 has one shared path/message and one rare path/message
    session1_events = [
        DummyEvent(base + timedelta(seconds=0), status=500, path="/shared", message="shared error"),
        DummyEvent(base + timedelta(seconds=5), status=404, path="/rare-only-once", message="rare message"),
    ]

    # Session 2 repeats the shared path/message, making only one of session1's entries rare
    session2_events = [
        DummyEvent(base + timedelta(minutes=1), status=500, path="/shared", message="shared error"),
        DummyEvent(base + timedelta(minutes=1, seconds=5), status=200, path="/home", message="ok"),
    ]

    sessions = [
        make_session("apache-rarity-1", base, session1_events),
        make_session("apache-rarity-2", base + timedelta(minutes=1), session2_events),
    ]

    df = sessions_to_features(sessions)
    row1 = df[df["session_id"] == "apache-rarity-1"].iloc[0]
    row2 = df[df["session_id"] == "apache-rarity-2"].iloc[0]

    # session1: paths are /shared and /rare-only-once -> only /rare-only-once is globally rare
    assert row1["apache_rare_path_ratio"] == 0.5

    # session1 messages are "shared error" and "rare message" -> only "rare message" is globally rare
    assert row1["apache_rare_error_message_ratio"] == 0.5

    # session2 has /shared and /home, where /home appears only once globally
    assert row2["apache_rare_path_ratio"] == 0.5

    # session2 has "shared error" and "ok", where "ok" appears once globally
    assert row2["apache_rare_error_message_ratio"] == 0.5