import json

import pandas as pd

from aegislog.cli_apache import main
from aegislog.incident.evidence import IncidentEvidence, SessionEvidence


def test_cli_apache_ai_explain_json(monkeypatch, tmp_path) -> None:
    fake_sessions = [object()]
    fake_df = pd.DataFrame(
        [
            {
                "session_id": "apache-session-1",
                "ensemble_score": 0.91,
                "anomaly_score": 0.91,
                "error_ratio": 0.50,
                "apache_error_vs_notice_ratio": 3.0,
                "apache_error_burst_max_per_minute": 12,
                "apache_5xx_burst_max_per_minute": 6,
                "apache_rare_error_message_ratio": 0.25,
                "apache_high_severity_ratio": 0.15,
                "apache_rare_hour": 0,
                "error_events": 18,
            }
        ]
    )

    fake_evidence = IncidentEvidence(
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

    def fake_load(args):
        return fake_sessions, fake_df

    def fake_find_session_by_id(sessions, session_id):
        assert session_id == "apache-session-1"
        return fake_sessions[0]

    def fake_build_evidence(session, row, model_type, threshold_percentile):
        assert model_type == "iforest"
        assert threshold_percentile == 99.0
        return fake_evidence

    def fake_generate(prompt):
        assert prompt["incident"]["incident_id"] == "apache:apache-session-1"
        assert prompt["incident"]["attack_pattern"] == "apache_error_spike"
        return {
            "summary": "Apache session shows bursty 5xx activity.",
            "evidence": ["5xx burst detected"],
            "hypothesis": "Possible application failure or hostile probing.",
            "caveats": ["Single-session view only"],
            "next_steps": ["Review Apache and upstream app logs"],
            "playbook_slug": "apache_error_spike",
            "playbook_notes": "Investigate bursty Apache errors.",
        }

    monkeypatch.setattr("aegislog.cli_apache.load_apache_sessions_for_cli", fake_load)
    monkeypatch.setattr("aegislog.cli_apache._find_session_by_id", fake_find_session_by_id)
    monkeypatch.setattr("aegislog.cli_apache.build_apache_incident_evidence", fake_build_evidence)
    monkeypatch.setattr("aegislog.cli_apache.generate_incident_analysis", fake_generate)

    output_file = tmp_path / "apache_ai_explain.json"

    rc = main(
        [
            "dummy.log",
            "--ai-explain",
            "--format",
            "json",
            "--output",
            str(output_file),
        ]
    )

    assert rc == 0
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["incident_id"] == "apache:apache-session-1"
    assert payload["attack_pattern"] == "apache_error_spike"
    assert payload["severity"] == "medium"
    assert "ai_analysis" in payload
    assert payload["ai_analysis"]["playbook_slug"] == "apache_error_spike"


def test_cli_apache_rejects_multiple_modes(capsys, monkeypatch) -> None:
    def fake_load(args):
        return [], pd.DataFrame()

    monkeypatch.setattr("aegislog.cli_apache.load_apache_sessions_for_cli", fake_load)

    rc = main(["dummy.log", "--explain", "--ai-explain"])

    captured = capsys.readouterr()
    assert rc == 1
    assert "Choose only one of --explain, --ai-explain, or --report." in captured.out