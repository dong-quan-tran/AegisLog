from pathlib import Path

import pandas as pd

from aegislog.cli_apache import main as apache_main


def test_cli_apache_smoke(tmp_path: Path, capsys):
    df = pd.DataFrame(
        [
            {
                "session_id": "s1",
                "score": 0.9,
                "error_ratio": 0.5,
                "apache_error_vs_notice_ratio": 3.0,
                "apache_error_burst_max_per_minute": 12,
                "apache_5xx_burst_max_per_minute": 6,
                "apache_rare_error_message_ratio": 0.4,
                "apache_high_severity_ratio": 0.2,
                "apache_rare_hour": 1,
            }
        ]
    )
    csv_path = tmp_path / "features.csv"
    df.to_csv(csv_path, index=False)

    exit_code = apache_main(
        ["--features-csv", str(csv_path), "--top", "5"]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Top 1 suspicious Apache sessions" in captured.out
    assert "s1" in captured.out
    assert "score=" in captured.out
    assert "notes:" in captured.out