from datetime import datetime

import pandas as pd

from aegislog.features.sessions import Session
from aegislog.incidents import build_apache_incident_evidence


def make_session() -> Session:
    return Session(
        session_id="apache-session-1",
        ip="203.0.113.10",
        user=None,
        user_agent=None,
        source_set=set(),
        start_time=datetime(2026, 5, 8, 10, 0, 0),
        end_time=datetime(2026, 5, 8, 10, 5, 0),
        events=[],
    )


def make_row(
    *,
    anomaly_score: float = 0.10,
    status_5xx: int = 0,
    error_events: int = 0,
    notice_events: int = 0,
    apache_5xx_streak_max: int = 0,
    apache_404_burst_max_per_minute: int = 0,
    apache_5xx_burst_max_per_minute: int = 0,
    apache_error_burst_max_per_minute: int = 0,
    apache_distinct_paths: int = 0,
    apache_rare_path_ratio: float = 0.0,
    apache_distinct_message_templates: int = 0,
    apache_rare_error_message_count: int = 0,
    apache_rare_error_message_ratio: float = 0.0,
    apache_rare_hour: int = 0,
    apache_error_vs_notice_ratio: float = 0.0,
    apache_high_severity_events: int = 0,
    apache_high_severity_ratio: float = 0.0,
    event_count: int = 10,
) -> pd.Series:
    return pd.Series(
        {
            "anomaly_score": anomaly_score,
            "status_5xx": status_5xx,
            "error_events": error_events,
            "notice_events": notice_events,
            "apache_5xx_streak_max": apache_5xx_streak_max,
            "apache_404_burst_max_per_minute": apache_404_burst_max_per_minute,
            "apache_5xx_burst_max_per_minute": apache_5xx_burst_max_per_minute,
            "apache_error_burst_max_per_minute": apache_error_burst_max_per_minute,
            "apache_distinct_paths": apache_distinct_paths,
            "apache_rare_path_ratio": apache_rare_path_ratio,
            "apache_distinct_message_templates": apache_distinct_message_templates,
            "apache_rare_error_message_count": apache_rare_error_message_count,
            "apache_rare_error_message_ratio": apache_rare_error_message_ratio,
            "apache_rare_hour": apache_rare_hour,
            "apache_error_vs_notice_ratio": apache_error_vs_notice_ratio,
            "apache_high_severity_events": apache_high_severity_events,
            "apache_high_severity_ratio": apache_high_severity_ratio,
            "event_count": event_count,
        }
    )


def test_build_apache_incident_evidence_classifies_error_spike() -> None:
    session = make_session()
    row = make_row(
        anomaly_score=0.25,
        status_5xx=12,
        error_events=20,
        apache_5xx_burst_max_per_minute=6,
        apache_error_burst_max_per_minute=12,
    )

    evidence = build_apache_incident_evidence(session, row)

    assert evidence.log_type == "apache_error"
    assert evidence.attack_pattern == "apache_error_spike"
    assert evidence.severity == "medium"
    assert evidence.priority == "medium"
    assert evidence.confidence == "medium"
    assert len(evidence.highlights) > 0
    assert "attack_pattern_reason" in evidence.extra


def test_build_apache_incident_evidence_classifies_rare_behavior() -> None:
    session = make_session()
    row = make_row(
        anomaly_score=0.12,
        error_events=4,
        apache_rare_error_message_count=3,
        apache_rare_error_message_ratio=0.45,
        apache_rare_path_ratio=0.40,
    )

    evidence = build_apache_incident_evidence(session, row)

    assert evidence.attack_pattern == "apache_rare_behavior"
    assert evidence.severity == "low"
    assert evidence.confidence == "medium"
    assert len(evidence.highlights) > 0
    assert evidence.extra["apache_rare_error_message_ratio"] == 0.45


def test_build_apache_incident_evidence_classifies_rare_hour_activity() -> None:
    session = make_session()
    row = make_row(
        anomaly_score=0.08,
        apache_rare_hour=1,
    )

    evidence = build_apache_incident_evidence(session, row)

    assert evidence.attack_pattern == "apache_rare_hour_activity"
    assert evidence.severity == "low"
    assert evidence.priority == "low"
    assert any("unusual hour" in h.lower() for h in evidence.highlights)


def test_build_apache_incident_evidence_defaults_to_generic_anomalous_session() -> None:
    session = make_session()
    row = make_row(
        anomaly_score=0.05,
        event_count=3,
    )

    evidence = build_apache_incident_evidence(session, row)

    assert evidence.attack_pattern == "apache_anomalous_session"
    assert evidence.severity == "low"
    assert evidence.confidence == "low"
    assert evidence.priority == "low"
    assert len(evidence.sessions) == 1
    assert evidence.sessions[0].event_type == "apache_session"


def test_build_apache_incident_evidence_sets_session_fields() -> None:
    session = make_session()
    row = make_row(
        anomaly_score=0.22,
        error_events=7,
        event_count=15,
    )

    evidence = build_apache_incident_evidence(session, row)
    session_ev = evidence.sessions[0]

    assert session_ev.session_id == "apache-session-1"
    assert session_ev.ip == "203.0.113.10"
    assert session_ev.event_count == 15
    assert session_ev.auth_failed == 0
    assert session_ev.auth_success == 0
    assert isinstance(session_ev.notes, list)