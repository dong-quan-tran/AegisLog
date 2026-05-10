from aegislog.ai.prompts import build_incident_analysis_prompt
from aegislog.incident.evidence import IncidentEvidence, SessionEvidence


def test_apache_ai_prompt_contains_expected_fields() -> None:
    evidence = IncidentEvidence(
        incident_id="apache:apache-session-1",
        log_type="apache_error",
        ip="203.0.113.20",
        user=None,
        model_type="iforest",
        feature_version="test-model",
        threshold_percentile=99.0,
        severity="medium",
        confidence="medium",
        priority="medium",
        attack_pattern="apache_error_spike",
        highlights=["5xx responses were bursty."],
        sessions=[
            SessionEvidence(
                session_id="apache-session-1",
                anomaly_score=0.91,
                start_time="2026-05-08T11:00:00",
                end_time="2026-05-08T11:05:00",
                ip="203.0.113.20",
                user=None,
                auth_failed=0,
                auth_success=0,
                event_count=20,
                event_type="apache_session",
                notes=["error spike within a single minute"],
            )
        ],
        extra={
            "error_events": 18,
            "avg_anomaly_score": 0.91,
            "status_5xx": 10,
            "apache_5xx_burst_max_per_minute": 6,
            "apache_error_burst_max_per_minute": 12,
            "apache_rare_error_message_ratio": 0.25,
            "apache_rare_path_ratio": 0.20,
            "apache_high_severity_ratio": 0.15,
        },
    )

    prompt = build_incident_analysis_prompt(evidence)

    assert prompt["incident"]["incident_id"] == "apache:apache-session-1"
    assert prompt["incident"]["ip"] == "203.0.113.20"
    assert prompt["incident"]["severity"] == "medium"
    assert prompt["incident"]["attack_pattern"] == "apache_error_spike"
    assert prompt["incident"]["primary_user"] is None

    assert prompt["incident"]["total_events"] == 18
    assert prompt["incident"]["avg_anomaly_score"] == 0.91
    assert prompt["incident"]["status_5xx"] == 10
    assert prompt["incident"]["apache_5xx_burst_max_per_minute"] == 6
    assert prompt["incident"]["apache_error_burst_max_per_minute"] == 12
    assert prompt["incident"]["apache_rare_error_message_ratio"] == 0.25
    assert prompt["incident"]["apache_rare_path_ratio"] == 0.20
    assert prompt["incident"]["apache_high_severity_ratio"] == 0.15

    assert prompt["evidence"]["highlights"] == ["5xx responses were bursty."]
    assert prompt["aggregates"]["total_incidents"] == 1
    assert "timeline_summary" in prompt
    assert "apache_error_spike" in prompt["timeline_summary"]