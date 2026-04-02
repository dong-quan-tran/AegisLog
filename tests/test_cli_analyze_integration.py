import json
import pytest

from aegislog.cli import main


def test_analyze_ssh_json_output(capsys, tmp_path):
    output_file = tmp_path / "analyze.json"

    main([
        "analyze",
        "data/loghub/SSH.log",
        "--log-type",
        "ssh_auth",
        "--model-path",
        "models/log_anomaly_iforest_ssh.joblib",
        "--top",
        "1",
        "--format",
        "json",
        "--output",
        str(output_file),
    ])

    data = json.loads(output_file.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    assert len(data) == 1
    item = data[0]
    assert "session_id" in item
    assert "ip" in item
    assert "anomaly_score" in item