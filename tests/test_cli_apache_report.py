import json

import pandas as pd

from aegislog.cli_apache import build_parser


def test_cli_apache_report_json(monkeypatch, tmp_path) -> None:
    fake_sessions = ["apache-session-1", "apache-session-2"]
    fake_df = pd.DataFrame(
        [
            {
                "session_id": "apache-session-1",
                "ensemble_score": 0.91,
                "error_ratio": 0.45,
                "error_events": 20,
                "apache_rare_hour": 1,
                "apache_5xx_burst_max_per_minute": 7,
                "apache_error_burst_max_per_minute": 12,
                "apache_rare_error_message_ratio": 0.40,
                "apache_high_severity_ratio": 0.20,
                "apache_error_vs_notice_ratio": 3.5,
            },
            {
                "session_id": "apache-session-2",
                "ensemble_score": 0.75,
                "error_ratio": 0.15,
                "error_events": 8,
                "apache_rare_hour": 0,
                "apache_5xx_burst_max_per_minute": 2,
                "apache_error_burst_max_per_minute": 4,
                "apache_rare_error_message_ratio": 0.10,
                "apache_high_severity_ratio": 0.00,
                "apache_error_vs_notice_ratio": 1.2,
            },
        ]
    )

    def fake_load(args):
        return fake_sessions, fake_df

    monkeypatch.setattr(
        "aegislog.cli_apache.load_apache_sessions_for_cli",
        fake_load,
    )

    output_file = tmp_path / "apache_report.json"

    parser = build_parser()
    args = parser.parse_args(
        [
            "dummy-apache.log",
            "--format",
            "json",
            "--report",
            "--output",
            str(output_file),
        ]
    )

    from aegislog.cli_apache import _report_apache_sessions

    result = _report_apache_sessions(args, fake_df)
    assert result == 0

    payload = json.loads(output_file.read_text(encoding="utf-8"))

    assert payload["total_sessions_considered"] == 2
    assert payload["rare_hour_sessions"] == 1
    assert payload["sessions_with_5xx_burst"] == 1
    assert payload["sessions_with_error_burst"] == 1
    assert payload["sessions_with_rare_templates"] == 1
    assert payload["sessions_with_high_severity_ratio"] == 1
    assert payload["sessions_with_error_dominance"] == 1
    assert payload["total_error_events"] == 28
    assert payload["top_session_ids"][0] == "apache-session-1"


def test_cli_apache_report_json_empty_after_filters(monkeypatch, tmp_path) -> None:
    fake_df = pd.DataFrame(
        columns=[
            "session_id",
            "ensemble_score",
            "error_ratio",
            "error_events",
            "apache_rare_hour",
            "apache_5xx_burst_max_per_minute",
            "apache_error_burst_max_per_minute",
            "apache_rare_error_message_ratio",
            "apache_high_severity_ratio",
            "apache_error_vs_notice_ratio",
        ]
    )

    output_file = tmp_path / "apache_report_empty.json"

    parser = build_parser()
    args = parser.parse_args(
        [
            "dummy-apache.log",
            "--format",
            "json",
            "--report",
            "--output",
            str(output_file),
        ]
    )

    from aegislog.cli_apache import _report_apache_sessions

    result = _report_apache_sessions(args, fake_df)
    assert result == 0
    assert not output_file.exists()