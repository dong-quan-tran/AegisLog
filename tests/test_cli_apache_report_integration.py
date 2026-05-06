import json
from pathlib import Path

import pytest

from aegislog.cli_apache import main as apache_main


def test_cli_apache_report_text_with_real_log(capsys):
    log_path = Path("data/loghub/Apache.log")
    if not log_path.exists():
        pytest.skip(f"Apache log sample not found at {log_path}")

    exit_code = apache_main([str(log_path), "--report"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Apache anomaly report:" in captured.out
    assert "total_sessions_considered=" in captured.out
    assert "top_session_ids:" in captured.out


def test_cli_apache_report_json_with_real_log(tmp_path):
    log_path = Path("data/loghub/Apache.log")
    if not log_path.exists():
        pytest.skip(f"Apache log sample not found at {log_path}")

    output_file = tmp_path / "apache_report.json"

    exit_code = apache_main(
        [
            str(log_path),
            "--report",
            "--format",
            "json",
            "--output",
            str(output_file),
        ]
    )

    assert exit_code == 0
    assert output_file.exists()

    payload = json.loads(output_file.read_text(encoding="utf-8"))

    assert isinstance(payload, dict)
    assert "total_sessions_considered" in payload
    assert "rare_hour_sessions" in payload
    assert "sessions_with_5xx_burst" in payload
    assert "sessions_with_error_burst" in payload
    assert "total_error_events" in payload
    assert "top_session_ids" in payload
    assert isinstance(payload["top_session_ids"], list)