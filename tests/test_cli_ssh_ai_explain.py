import json
from datetime import datetime

import pandas as pd

from aegislog.cli_ssh import build_parser
from aegislog.incident.evidence import IncidentEvidence, SessionEvidence


def test_cli_ssh_ai_explain_json(monkeypatch, tmp_path) -> None:
    fake_sessions = ["dummy-session"]
    fake_df = pd.DataFrame(
        [
            {
                "session_id": "ssh-session-1",
                "ensemble_score": 0.95,
                "anomaly_score": 0.95,
                "event_count": 42,
                "auth_failed": 30,
                "auth_success": 1,
                "auth_fail_ratio": 30 / 31,
                "is_anomalous": True,
            }
        ]
    )

    class FakeIncident:
        def __init__(self) -> None:
            self.incident_id = "ip:198.51.100.10#0"
            self.ip = "198.51.100.10"
            self.severity = "high"
            self.severity_reason = "test severity reason"
            self.confidence = "high"
            self.confidence_reason = "test confidence reason"
            self.priority = "critical"
            self.priority_score = 85
            self.priority_reason = "test priority reason"
            self.attack_pattern = "brute_force"
            self.attack_pattern_reason = "test pattern reason"
            self.session_ids = ["ssh-session-1"]
            self.total_events = 42
            self.avg_anomaly_score = 0.95
            self.auth_failed = 30
            self.auth_success = 1
            self.auth_fail_ratio = 30 / 31
            self.first_seen = datetime(2026, 5, 9, 12, 0, 0)
            self.last_seen = datetime(2026, 5, 9, 12, 5, 0)
            self.primary_user = "alice"
            self.targeted_users = ["alice", "bob"]

    fake_incident = FakeIncident()
    fake_incidents = [fake_incident]

    fake_timeline = []

    fake_evidence = IncidentEvidence(
        incident_id=fake_incident.incident_id,
        log_type="ssh_auth",
        ip=fake_incident.ip,
        user=fake_incident.primary_user,
        model_type="iforest",
        feature_version="test-model",
        threshold_percentile=99.0,
        severity=fake_incident.severity,
        confidence=fake_incident.confidence,
        priority=fake_incident.priority,
        attack_pattern=fake_incident.attack_pattern,
        highlights=["High failed-auth ratio consistent with brute force."],
        sessions=[
            SessionEvidence(
                session_id="ssh-session-1",
                anomaly_score=0.95,
                start_time="2026-05-09T12:00:00",
                end_time="2026-05-09T12:05:00",
                ip=fake_incident.ip,
                user=fake_incident.primary_user,
                auth_failed=30,
                auth_success=1,
                event_count=42,
                event_type="failures_then_success",
                notes=["test session evidence"],
            )
        ],
        extra={
            "total_events": fake_incident.total_events,
            "avg_anomaly_score": fake_incident.avg_anomaly_score,
            "auth_failed": fake_incident.auth_failed,
            "auth_success": fake_incident.auth_success,
            "auth_fail_ratio": fake_incident.auth_fail_ratio,
            "auth_failed_streak_max": 10,
            "auth_burst_max_per_minute": 20,
            "first_seen": fake_incident.first_seen.isoformat(),
            "last_seen": fake_incident.last_seen.isoformat(),
        },
    )

    def fake_load(args, *, anomalous_only: bool, restrict_sessions_to_df: bool):
        return fake_sessions, fake_df, fake_incidents

    def fake_build_timeline(inc, sessions, df):
        assert inc is fake_incident
        return fake_timeline

    def fake_build_evidence(inc, timeline, log_type, model_type, threshold_percentile):
        assert inc is fake_incident
        assert log_type == "ssh_auth"
        assert model_type == "iforest"
        assert threshold_percentile == 99.0
        return fake_evidence

    def fake_generate(prompt):
        assert prompt["incident"]["incident_id"] == fake_incident.incident_id
        assert prompt["incident"]["attack_pattern"] == "brute_force"
        return {
            "summary": "SSH incident shows a brute-force pattern against alice.",
            "evidence": [
                "High failed-auth ratio",
                "Failures followed by success",
            ],
            "hypothesis": "The attacker likely guessed alice's password.",
            "caveats": ["Single-host view only"],
            "next_steps": [
                "Rotate credentials and keys for alice",
                "Review host logs around the incident window",
            ],
            "playbook_slug": "ssh_brute_force",
            "playbook_notes": "Standard SSH brute-force incident response.",
        }

    monkeypatch.setattr(
        "aegislog.cli_ssh.load_ssh_incidents_for_cli",
        fake_load,
    )
    monkeypatch.setattr(
        "aegislog.cli_ssh.build_incident_timeline",
        fake_build_timeline,
    )
    monkeypatch.setattr(
        "aegislog.cli_ssh.build_ssh_incident_evidence",
        fake_build_evidence,
    )
    monkeypatch.setattr(
        "aegislog.cli_ssh.generate_incident_analysis",
        fake_generate,
    )

    output_file = tmp_path / "ssh_ai_explain.json"

    parser = build_parser()
    args = parser.parse_args(
        [
            "ai-explain",
            "dummy.log",
            "--log-type",
            "ssh_auth",
            "--format",
            "json",
            "--output",
            str(output_file),
        ]
    )

    args.func(args)

    payload = json.loads(output_file.read_text(encoding="utf-8"))

    assert payload["incident_id"] == fake_incident.incident_id
    assert payload["log_type"] == "ssh_auth"
    assert payload["ip"] == fake_incident.ip
    assert payload["attack_pattern"] == "brute_force"
    assert "ai_analysis" in payload

    analysis = payload["ai_analysis"]
    assert analysis["summary"].startswith("SSH incident shows a brute-force pattern")
    assert analysis["playbook_slug"] == "ssh_brute_force"
    assert "High failed-auth ratio" in analysis["evidence"][0]