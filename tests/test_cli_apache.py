from pathlib import Path

import pytest

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