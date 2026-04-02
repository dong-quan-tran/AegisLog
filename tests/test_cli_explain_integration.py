import json
from aegislog.cli import main


def test_explain_ssh_json_output(tmp_path):
    output_file = tmp_path / "explain.json"

    main([
        "explain",
        "data/loghub/SSH.log",
        "--log-type",
        "ssh_auth",
        "--model-path",
        "models/log_anomaly_iforest_ssh.joblib",
        "--index",
        "0",
        "--format",
        "json",
        "--output",
        str(output_file),
    ])

    data = json.loads(output_file.read_text(encoding="utf-8"))
    assert "incident" in data
    assert "summary" in data
    assert "local_explanation" in data
    assert "llm_prompt" in data
    assert data["incident"]["incident_id"].startswith("ip:")
    assert data["incident"]["severity"] in {"high", "medium", "low"}