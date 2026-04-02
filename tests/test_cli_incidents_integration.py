import json
from aegislog.cli import main


def test_incidents_ssh_json_output(tmp_path):
    output_file = tmp_path / "incidents.json"

    main([
        "incidents",
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
    assert "incident" in item
    assert "summary" in item
    assert "local_explanation" in item
    assert "llm_prompt" in item
    assert item["incident"]["severity"] in {"high", "medium", "low"}