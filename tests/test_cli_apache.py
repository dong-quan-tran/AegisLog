from pathlib import Path

import pytest

import json

from aegislog.cli_apache import main as apache_main


def test_cli_apache_smoke_with_real_log(capsys):
    # This test assumes the LogHub Apache.log sample is available
    log_path = Path("data/loghub/Apache.log")
    if not log_path.exists():
        pytest.skip(f"Apache log sample not found at {log_path}")

    exit_code = apache_main(
        [str(log_path), "--top", "5"]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Top " in captured.out
    assert "suspicious Apache sessions" in captured.out
    assert "score=" in captured.out
    assert "notes:" in captured.out


def test_cli_apache_smoke_with_real_log(capsys):
    # This test assumes the LogHub Apache.log sample is available
    log_path = Path("data/loghub/Apache.log")
    if not log_path.exists():
        pytest.skip(f"Apache log sample not found at {log_path}")

    exit_code = apache_main(
        [str(log_path), "--top", "5"]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Top " in captured.out
    assert "suspicious Apache sessions" in captured.out
    assert "score=" in captured.out
    assert "notes:" in captured.out


def test_cli_apache_json_top_sessions_with_real_log(tmp_path):
    log_path = Path("data/loghub/Apache.log")
    if not log_path.exists():
        pytest.skip(f"Apache log sample not found at {log_path}")

    output_file = tmp_path / "apache_top.json"

    exit_code = apache_main(
        [
            str(log_path),
            "--top",
            "5",
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
    assert len(payload) > 0
    first = payload[0]
    assert "session_id" in first
    assert "score" in first
    assert "apache_notes" in first