import json
from pathlib import Path

import pytest

from aegislog.cli_apache import main as apache_main


def test_cli_apache_report_rare_hour_only_with_real_log(capsys):
    log_path = Path("data/loghub/Apache.log")
    if not log_path.exists():
        pytest.skip(f"Apache log sample not found at {log_path}")

    exit_code = apache_main([str(log_path), "--report", "--rare-hour-only"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Apache anomaly report:" in captured.out
    assert "rare_hour_sessions=" in captured.out


def test_cli_apache_json_top_sessions_with_min_error_events(tmp_path):
    log_path = Path("data/loghub/Apache.log")
    if not log_path.exists():
        pytest.skip(f"Apache log sample not found at {log_path}")

    output_file = tmp_path / "apache_filtered_top.json"

    exit_code = apache_main(
        [
            str(log_path),
            "--top",
            "5",
            "--min-error-events",
            "100",
            "--format",
            "json",
            "--output",
            str(output_file),
        ]
    )

    assert exit_code == 0
    assert output_file.exists()

    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert isinstance(payload, list)


def test_cli_apache_explain_no_sessions_after_filter(capsys):
    log_path = Path("data/loghub/Apache.log")
    if not log_path.exists():
        pytest.skip(f"Apache log sample not found at {log_path}")

    exit_code = apache_main(
        [
            str(log_path),
            "--explain",
            "--first",
            "--min-5xx-burst",
            "999999",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "No sessions found after filtering." in captured.out