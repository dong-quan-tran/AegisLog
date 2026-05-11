import pandas as pd

from aegislog.ai.client import LLMError
from aegislog import cli_apache


class DummyEvidence:
    incident_id = "inc-123"
    log_type = "apache_error"
    ip = "1.2.3.4"
    severity = "high"
    attack_pattern = "burst-errors"

    def __init__(self):
        self.highlights = ["burst detected"]
        self.extra = {
            "status_5xx": 7,
            "error_events": 12,
            "apache_rare_error_message_count": 2,
            "apache_rare_error_message_ratio": 0.5,
            "apache_rare_path_ratio": 0.25,
        }

    def to_dict(self):
        return {
            "incident_id": self.incident_id,
            "log_type": self.log_type,
            "ip": self.ip,
            "severity": self.severity,
            "attack_pattern": self.attack_pattern,
            "highlights": self.highlights,
            "extra": self.extra,
        }


class DummySession:
    session_id = "sess-1"


def _sample_df():
    return pd.DataFrame(
        [
            {
                "session_id": "sess-1",
                "ensemble_score": 0.99,
                "error_ratio": 0.5,
                "apache_error_vs_notice_ratio": 3.0,
                "apache_error_burst_max_per_minute": 12,
                "apache_5xx_burst_max_per_minute": 7,
                "apache_rare_error_message_ratio": 0.5,
                "apache_high_severity_ratio": 0.2,
                "apache_rare_hour": 1,
                "error_events": 12,
            }
        ]
    )


def test_ai_explain_handles_llmerror_gracefully(monkeypatch, capsys):
    monkeypatch.setattr(
        cli_apache,
        "load_apache_sessions_for_cli",
        lambda args: ([DummySession()], _sample_df()),
    )
    monkeypatch.setattr(
        cli_apache,
        "build_apache_incident_evidence",
        lambda *args, **kwargs: DummyEvidence(),
    )
    monkeypatch.setattr(
        cli_apache,
        "build_incident_analysis_prompt",
        lambda evidence: "prompt",
    )

    def raise_llmerror(prompt):
        raise LLMError("upstream failed")

    monkeypatch.setattr(
        cli_apache,
        "generate_incident_analysis",
        raise_llmerror,
    )

    rc = cli_apache.main(["sample.log", "--ai-explain"])

    captured = capsys.readouterr()
    assert rc == 1
    assert "AI analysis failed: upstream failed" in captured.out


def test_ai_explain_json_handles_llmerror_gracefully(monkeypatch, capsys):
    monkeypatch.setattr(
        cli_apache,
        "load_apache_sessions_for_cli",
        lambda args: ([DummySession()], _sample_df()),
    )
    monkeypatch.setattr(
        cli_apache,
        "build_apache_incident_evidence",
        lambda *args, **kwargs: DummyEvidence(),
    )
    monkeypatch.setattr(
        cli_apache,
        "build_incident_analysis_prompt",
        lambda evidence: "prompt",
    )

    def raise_llmerror(prompt):
        raise LLMError("upstream failed")

    monkeypatch.setattr(
        cli_apache,
        "generate_incident_analysis",
        raise_llmerror,
    )

    rc = cli_apache.main(["sample.log", "--ai-explain", "--format", "json"])

    captured = capsys.readouterr()
    assert rc == 1
    assert "AI analysis failed: upstream failed" in captured.out