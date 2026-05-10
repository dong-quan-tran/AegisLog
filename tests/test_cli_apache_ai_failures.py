import pandas as pd
import pytest

from aegislog.ai.client import LLMError
from aegislog.cli_apache import main, build_parser
from aegislog.cli_apache import _ai_explain_apache_session


def test_cli_apache_ai_explain_propagates_llm_error(monkeypatch) -> None:
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

    class FakeEvidence:
        def __init__(self) -> None:
            self.incident_id = "apache:apache-session-1"
            self.log_type = "apache_error"
            self.ip = "203.0.113.20"
            self.user = None
            self.severity = "medium"
            self.attack_pattern = "apache_error_spike"
            self.highlights = ["5xx responses were bursty."]
            self.sessions = []
            self.extra = {
                "error_events": 18,
                "avg_anomaly_score": 0.91,
                "status_5xx": 10,
                "apache_5xx_burst_max_per_minute": 6,
                "apache_error_burst_max_per_minute": 12,
                "apache_rare_error_message_ratio": 0.25,
                "apache_rare_path_ratio": 0.20,
                "apache_high_severity_ratio": 0.15,
            }

        def to_dict(self):
            return {
                "incident_id": self.incident_id,
                "attack_pattern": self.attack_pattern,
            }

    def fake_load(args):
        return fake_sessions, fake_df

    def fake_find_session_by_id(sessions, session_id):
        return fake_sessions[0]

    def fake_build_evidence(session, row, model_type, threshold_percentile):
        return FakeEvidence()

    def fake_generate(prompt):
        raise LLMError("mock Apache AI failure")

    monkeypatch.setattr("aegislog.cli_apache.load_apache_sessions_for_cli", fake_load)
    monkeypatch.setattr("aegislog.cli_apache._find_session_by_id", fake_find_session_by_id)
    monkeypatch.setattr("aegislog.cli_apache.build_apache_incident_evidence", fake_build_evidence)
    monkeypatch.setattr("aegislog.cli_apache.generate_incident_analysis", fake_generate)

    with pytest.raises(LLMError, match="mock Apache AI failure"):
        main(["dummy.log", "--ai-explain"])


def test_cli_apache_ai_explain_no_sessions_after_filter(capsys) -> None:
    fake_df = pd.DataFrame(
        columns=[
            "session_id",
            "ensemble_score",
            "anomaly_score",
            "error_ratio",
            "apache_error_vs_notice_ratio",
            "apache_error_burst_max_per_minute",
            "apache_5xx_burst_max_per_minute",
            "apache_rare_error_message_ratio",
            "apache_high_severity_ratio",
            "apache_rare_hour",
            "error_events",
        ]
    )

    parser = build_parser()
    args = parser.parse_args(["dummy.log", "--ai-explain"])

    rc = _ai_explain_apache_session(args, [], fake_df)
    captured = capsys.readouterr()

    assert rc == 0
    assert "No sessions found." in captured.out