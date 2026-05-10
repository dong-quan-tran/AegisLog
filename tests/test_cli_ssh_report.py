import json

import pandas as pd

from aegislog.cli_ssh import build_parser


def test_cli_ssh_report_json(monkeypatch, tmp_path) -> None:
    fake_sessions = ["s1", "s2", "s3"]
    fake_df = pd.DataFrame(
        [
            {"session_id": "s1", "is_anomalous": True},
            {"session_id": "s2", "is_anomalous": False},
            {"session_id": "s3", "is_anomalous": True},
        ]
    )

    class FakeIncident:
        def __init__(
            self,
            incident_id: str,
            ip: str,
            severity: str,
            confidence: str,
            attack_pattern: str,
        ) -> None:
            self.incident_id = incident_id
            self.ip = ip
            self.severity = severity
            self.confidence = confidence
            self.attack_pattern = attack_pattern

    fake_incidents = [
        FakeIncident("inc-1", "198.51.100.10", "high", "high", "brute_force"),
        FakeIncident("inc-2", "198.51.100.11", "medium", "medium", "password_spray"),
    ]

    fake_report = {
        "total_sessions": 3,
        "anomalous_sessions": 2,
        "anomalous_session_percent": 66.67,
        "total_incidents": 2,
        "severity_counts": {"high": 1, "medium": 1},
        "confidence_counts": {"high": 1, "medium": 1},
        "top_incident_ips": [
            {"ip": "198.51.100.10", "incident_count": 1},
            {"ip": "198.51.100.11", "incident_count": 1},
        ],
        "top_targeted_users": [
            {"user": "alice", "incident_count": 1},
            {"user": "bob", "incident_count": 1},
        ],
    }

    def fake_load(args, *, anomalous_only: bool, restrict_sessions_to_df: bool):
        return fake_sessions, fake_df, fake_incidents

    def fake_build_report(
        incidents,
        total_sessions: int,
        anomalous_sessions: int,
        top_n: int,
    ):
        assert len(incidents) == 2
        assert total_sessions == 3
        assert anomalous_sessions == 2
        assert top_n == 5
        return fake_report

    monkeypatch.setattr(
        "aegislog.cli_ssh.load_ssh_incidents_for_cli",
        fake_load,
    )
    monkeypatch.setattr(
        "aegislog.cli_ssh.build_incident_report",
        fake_build_report,
    )

    output_file = tmp_path / "ssh_report.json"

    parser = build_parser()
    args = parser.parse_args(
        [
            "report",
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

    assert payload["total_sessions"] == 3
    assert payload["anomalous_sessions"] == 2
    assert payload["total_incidents"] == 2
    assert payload["severity_counts"]["high"] == 1
    assert payload["confidence_counts"]["medium"] == 1
    assert payload["top_incident_ips"][0]["ip"] == "198.51.100.10"


def test_cli_ssh_report_json_empty_after_filters(monkeypatch, tmp_path) -> None:
    fake_sessions = ["s1", "s2"]
    fake_df = pd.DataFrame(
        [
            {"session_id": "s1", "is_anomalous": True},
            {"session_id": "s2", "is_anomalous": False},
        ]
    )

    fake_empty_report = {
        "total_sessions": 2,
        "anomalous_sessions": 1,
        "anomalous_session_percent": 50.0,
        "total_incidents": 0,
        "severity_counts": {},
        "confidence_counts": {},
        "top_incident_ips": [],
        "top_targeted_users": [],
    }

    def fake_load(args, *, anomalous_only: bool, restrict_sessions_to_df: bool):
        return fake_sessions, fake_df, []

    def fake_build_report(
        incidents,
        total_sessions: int,
        anomalous_sessions: int,
        top_n: int,
    ):
        assert incidents == []
        assert total_sessions == 2
        assert anomalous_sessions == 1
        assert top_n == 5
        return fake_empty_report

    monkeypatch.setattr(
        "aegislog.cli_ssh.load_ssh_incidents_for_cli",
        fake_load,
    )
    monkeypatch.setattr(
        "aegislog.cli_ssh.build_incident_report",
        fake_build_report,
    )

    output_file = tmp_path / "ssh_report_empty.json"

    parser = build_parser()
    args = parser.parse_args(
        [
            "report",
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

    assert payload["total_sessions"] == 2
    assert payload["anomalous_sessions"] == 1
    assert payload["total_incidents"] == 0
    assert payload["top_incident_ips"] == []
    assert payload["top_targeted_users"] == []