import json
from pathlib import Path

import pytest

from aegislog.cli_apache import main as apache_main


def test_cli_apache_explain_text_with_real_log(capsys):
    log_path = Path("data/loghub/Apache.log")
    if not log_path.exists():
        pytest.skip(f"Apache log sample not found at {log_path}")

    exit_code = apache_main(
        [str(log_path), "--explain", "--first"]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Explaining Apache session at index 0:" in captured.out
    assert "highlights:" in captured.out
    assert "metrics:" in captured.out


def test_cli_apache_explain_json_with_real_log(tmp_path):
    log_path = Path("data/loghub/Apache.log")
    if not log_path.exists():
        pytest.skip(f"Apache log sample not found at {log_path}")

    output_file = tmp_path / "apache_explain.json"

    exit_code = apache_main(
        [
            str(log_path),
            "--explain",
            "--first",
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
    assert payload["incident_id"].startswith("apache:")
    assert payload["log_type"] == "apache_error"
    assert "highlights" in payload
    assert isinstance(payload["highlights"], list)
    assert "sessions" in payload
    assert isinstance(payload["sessions"], list)
    assert len(payload["sessions"]) == 1
    assert "extra" in payload
    assert isinstance(payload["extra"], dict)