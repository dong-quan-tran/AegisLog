import json
from datetime import datetime, timedelta

import pandas as pd

from aegislog.features.sessions import Session
from aegislog.incidents import build_apache_incident_evidence


def test_build_apache_incident_evidence_json_serializable():
    start = datetime(2025, 1, 1, 2, 0, 0)

    session = Session(
        session_id="apache-session-1",
        ip="5.6.7.8",
        user=None,
        user_agent=None,
        start_time=start,
        end_time=start + timedelta(minutes=1),
        events=[],
        source_set={"apache_error"},
    )

    row = pd.Series(
        {
            "session_id": "apache-session-1",
            "event_count": 8,
            "anomaly_score": 0.31,
            "status_5xx": 5,
            "error_events": 5,
            "notice_events": 3,
            "apache_5xx_streak_max": 5,
            "apache_404_burst_max_per_minute": 0,
            "apache_5xx_burst_max_per_minute": 5,
            "apache_error_burst_max_per_minute": 5,
            "apache_distinct_paths": 2,
            "apache_rare_path_ratio": 0.5,
            "apache_distinct_message_templates": 5,
            "apache_rare_error_message_count": 5,
            "apache_rare_error_message_ratio": 1.0,
            "apache_rare_hour": 1,
            "apache_error_vs_notice_ratio": 5 / 3,
            "apache_high_severity_events": 5,
            "apache_high_severity_ratio": 5 / 8,
        }
    )

    evidence = build_apache_incident_evidence(
        session,
        row,
        model_type="iforest",
        threshold_percentile=99.0,
    )

    assert evidence.incident_id == "apache:apache-session-1"
    assert evidence.log_type == "apache_error"
    assert evidence.model_type == "iforest"
    assert len(evidence.sessions) == 1
    assert evidence.highlights
    assert evidence.extra["status_5xx"] == 5
    assert evidence.extra["apache_rare_error_message_count"] == 5

    payload = evidence.to_dict()
    assert payload["sessions"][0]["session_id"] == "apache-session-1"

    json_text = json.dumps(payload)
    assert isinstance(json_text, str)