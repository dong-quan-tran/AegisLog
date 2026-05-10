import pandas as pd

from aegislog.ai.client import LLMError
from aegislog.cli_ssh import build_parser


def test_cli_ssh_ai_explain_handles_llm_error(capsys, monkeypatch) -> None:
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
            self.confidence = "high"
            self.priority = "critical"
            self.priority_score = 85
            self.attack_pattern = "brute_force"
            self.session_ids = ["ssh-session-1"]
            self.total_events = 42
            self.avg_anomaly_score = 0.95
            self.auth_failed = 30
            self.auth_success = 1
            self.auth_fail_ratio = 30 / 31

    fake_incident = FakeIncident()

    class FakeEvidence:
        def __init__(self) -> None:
            self.incident_id = fake_incident.incident_id
            self.log_type = "ssh_auth"
            self.ip = fake_incident.ip
            self.user = "alice"
            self.model_type = "iforest"
            self.feature_version = "test-model"
            self.threshold_percentile = 99.0
            self.severity = fake_incident.severity
            self.confidence = fake_incident.confidence
            self.priority = fake_incident.priority
            self.attack_pattern = fake_incident.attack_pattern
            self.highlights = ["High failed-auth ratio"]
            self.sessions = []
            self.extra = {
                "total_events": fake_incident.total_events,
                "avg_anomaly_score": fake_incident.avg_anomaly_score,
                "auth_failed": fake_incident.auth_failed,
                "auth_success": fake_incident.auth_success,
                "auth_fail_ratio": fake_incident.auth_fail_ratio,
            }

        def to_dict(self):
            return {"incident_id": self.incident_id}

    def fake_load(args, *, anomalous_only: bool, restrict_sessions_to_df: bool):
        return fake_sessions, fake_df, [fake_incident]

    def fake_timeline(inc, sessions, df):
        return []

    def fake_build_evidence(inc, timeline, log_type, model_type, threshold_percentile):
        return FakeEvidence()

    def fake_generate(prompt):
        raise LLMError("mock SSH AI failure")

    monkeypatch.setattr("aegislog.cli_ssh.load_ssh_incidents_for_cli", fake_load)
    monkeypatch.setattr("aegislog.cli_ssh.build_incident_timeline", fake_timeline)
    monkeypatch.setattr("aegislog.cli_ssh.build_ssh_incident_evidence", fake_build_evidence)
    monkeypatch.setattr("aegislog.cli_ssh.generate_incident_analysis", fake_generate)

    parser = build_parser()
    args = parser.parse_args(
        [
            "ai-explain",
            "dummy.log",
            "--log-type",
            "ssh_auth",
        ]
    )

    args.func(args)
    captured = capsys.readouterr()
    assert "[AI analysis unavailable] mock SSH AI failure" in captured.out


def test_cli_ssh_explain_use_llm_handles_llm_error(capsys, monkeypatch) -> None:
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
            self.severity_reason = None
            self.confidence = "high"
            self.confidence_reason = None
            self.priority = "critical"
            self.priority_score = 85
            self.priority_reason = None
            self.attack_pattern = "brute_force"
            self.attack_pattern_reason = None
            self.session_ids = ["ssh-session-1"]
            self.total_events = 42
            self.avg_anomaly_score = 0.95
            self.auth_failed = 30
            self.auth_success = 1
            self.auth_fail_ratio = 30 / 31
            self.first_seen = None
            self.last_seen = None
            self.primary_user = "alice"
            self.targeted_users = ["alice"]

    class FakeSummary:
        title = "Brute-force SSH activity"
        description = "Repeated failed logins followed by a success."

    class FakeLLMPrompt:
        prompt = "Legacy LLM prompt text"

    fake_incident = FakeIncident()

    class FakeEvidence:
        def __init__(self) -> None:
            self.incident_id = fake_incident.incident_id
            self.log_type = "ssh_auth"
            self.ip = fake_incident.ip
            self.user = fake_incident.primary_user
            self.model_type = "iforest"
            self.feature_version = "test-model"
            self.threshold_percentile = 99.0
            self.severity = fake_incident.severity
            self.confidence = fake_incident.confidence
            self.priority = fake_incident.priority
            self.attack_pattern = fake_incident.attack_pattern
            self.highlights = ["High failed-auth ratio"]
            self.sessions = []
            self.extra = {
                "total_events": fake_incident.total_events,
                "avg_anomaly_score": fake_incident.avg_anomaly_score,
                "auth_failed": fake_incident.auth_failed,
                "auth_success": fake_incident.auth_success,
                "auth_fail_ratio": fake_incident.auth_fail_ratio,
            }

        def to_dict(self):
            return {"incident_id": self.incident_id}

    def fake_load(args, *, anomalous_only: bool, restrict_sessions_to_df: bool):
        return fake_sessions, fake_df, [fake_incident]

    def fake_timeline(inc, sessions, df):
        return []

    def fake_summarize(inc):
        return FakeSummary()

    def fake_local_explanation(inc, summary):
        return "Local explanation text"

    def fake_build_llm_prompt(inc, summary):
        return FakeLLMPrompt()

    def fake_build_evidence(inc, timeline, log_type, model_type, threshold_percentile):
        return FakeEvidence()

    def fake_generate(prompt):
        raise LLMError("mock SSH explain failure")

    monkeypatch.setattr("aegislog.cli_ssh.load_ssh_incidents_for_cli", fake_load)
    monkeypatch.setattr("aegislog.cli_ssh.build_incident_timeline", fake_timeline)
    monkeypatch.setattr("aegislog.cli_ssh.summarize_incident", fake_summarize)
    monkeypatch.setattr("aegislog.cli_ssh.local_incident_explanation", fake_local_explanation)
    monkeypatch.setattr("aegislog.cli_ssh.build_incident_llm_prompt", fake_build_llm_prompt)
    monkeypatch.setattr("aegislog.cli_ssh.build_ssh_incident_evidence", fake_build_evidence)
    monkeypatch.setattr("aegislog.cli_ssh.generate_incident_analysis", fake_generate)

    parser = build_parser()
    args = parser.parse_args(
        [
            "explain",
            "dummy.log",
            "--log-type",
            "ssh_auth",
            "--use-llm",
        ]
    )

    args.func(args)
    captured = capsys.readouterr()
    assert "[AI analysis unavailable] mock SSH explain failure" in captured.out