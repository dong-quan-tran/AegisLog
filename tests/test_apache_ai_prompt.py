from datetime import datetime

import pandas as pd

from aegislog.features.sessions import Session
from aegislog.incidents import build_apache_incident_evidence
from aegislog.cli_apache import _build_apache_ai_prompt


def make_session() -> Session:
    return Session(
        session_id="apache-session-ai-1",
        ip="203.0.113.20",
        user=None,
        user_agent=None,
        source_set=set(),
        start_time=datetime(2026, 5, 8, 11, 0, 0),
        end_time=datetime(2026, 5, 8, 11, 5, 0),
        events=[],
    )


def make_row() -> pd.Series:
    return pd.Series(
        {
            "anomaly_score": 0.25,
            "status_5xx": 10,
            "error_events": 18,
            "notice_events": 5,
            "apache_5xx_streak_max": 0,
            "apache_404_burst_max_per_minute": 0,
            "apache_5xx_burst_max_per_minute": 6,
            "apache_error_burst_max_per_minute": 12,
            "apache_distinct_paths": 4,
            "apache_rare_path_ratio": 0.2,
            "apache_distinct_message_templates": 3,
            "apache_rare_error_message_count": 2,
            "apache_rare_error_message_ratio": 0.25,
            "apache_rare_hour": 0,
            "apache_error_vs_notice_ratio": 3.0,
            "apache_high_severity_events": 1,
            "apache_high_severity_ratio": 0.15,
            "event_count": 20,
        }
    )


def test_build_apache_ai_prompt_shape_and_fields() -> None:
    session = make_session()
    row = make_row()

    evidence = build_apache_incident_evidence(session, row)
    prompt = _build_apache_ai_prompt(evidence)

    assert "incident" in prompt
    assert "evidence" in prompt
    assert "timeline_summary" in prompt
    assert "aggregates" in prompt

    incident = prompt["incident"]
    assert incident["incident_id"] == evidence.incident_id
    assert incident["ip"] == evidence.ip
    assert incident["attack_pattern"] == evidence.attack_pattern
    assert incident["severity"] == evidence.severity
    assert incident["total_events"] == evidence.extra["error_events"]
    assert incident["apache_5xx_burst_max_per_minute"] == evidence.extra["apache_5xx_burst_max_per_minute"]

    evidence_block = prompt["evidence"]
    assert evidence_block["highlights"] == evidence.highlights

    assert prompt["aggregates"]["total_incidents"] == 1
    assert "Apache error session" in prompt["timeline_summary"]