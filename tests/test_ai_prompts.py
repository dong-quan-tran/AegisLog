from aegislog.ai.prompts import build_incident_analysis_prompt
from aegislog.incident.evidence import IncidentEvidence, SessionEvidence


def test_build_incident_analysis_prompt_for_ssh() -> None:
    evidence = IncidentEvidence(
        incident_id="ip:198.51.100.10#0",
        log_type="ssh_auth",
        ip="198.51.100.10",
        user="alice",
        model_type="iforest",
        feature_version="test-model",
        threshold_percentile=99.0,
        severity="high",
        confidence="high",
        priority="critical",
        attack_pattern="brute_force",
        highlights=[
            "High failed-auth ratio",
            "Multiple failed attempts followed by one success",
        ],
        sessions=[
            SessionEvidence(
                session_id="ssh-session-1",
                anomaly_score=0.95,
                start_time="2026-05-09T12:00:00",
                end_time="2026-05-09T12:05:00",
                ip="198.51.100.10",
                user="alice",
                auth_failed=30,
                auth_success=1,
                event_count=42,
                event_type="failures_then_success",
                notes=["test session evidence"],
            )
        ],
        extra={
            "total_events": 42,
            "avg_anomaly_score": 0.95,
            "auth_failed": 30,
            "auth_success": 1,
            "auth_fail_ratio": 30 / 31,
            "auth_failed_streak_max": 10,
            "auth_burst_max_per_minute": 20,
            "first_seen": "2026-05-09T12:00:00",
            "last_seen": "2026-05-09T12:05:00",
        },
    )

    prompt = build_incident_analysis_prompt(evidence)

    assert prompt["incident"]["incident_id"] == "ip:198.51.100.10#0"
    assert prompt["incident"]["ip"] == "198.51.100.10"
    assert prompt["incident"]["severity"] == "high"
    assert prompt["incident"]["attack_pattern"] == "brute_force"
    assert prompt["incident"]["primary_user"] == "alice"
    assert prompt["incident"]["auth_failed"] == 30
    assert prompt["incident"]["auth_success"] == 1
    assert prompt["incident"]["auth_fail_ratio"] == 30 / 31

    assert prompt["evidence"]["highlights"][0] == "High failed-auth ratio"
    assert prompt["aggregates"]["total_incidents"] == 1
    assert "timeline_summary" in prompt


def test_build_incident_analysis_prompt_for_apache() -> None:
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

    assert prompt["evidence"]["highlights"] == ["5xx responses were bursty."]
    assert prompt["aggregates"]["total_incidents"] == 1
    assert "timeline_summary" in prompt