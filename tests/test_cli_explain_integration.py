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


def test_explain_ssh_json_output_filtered_by_pattern(tmp_path):
    output_file = tmp_path / "explain_pattern.json"

    main([
        "explain",
        "data/loghub/SSH.log",
        "--log-type",
        "ssh_auth",
        "--model-path",
        "models/log_anomaly_iforest_ssh.joblib",
        "--first",
        "--format",
        "json",
        "--output",
        str(output_file),
        "--pattern",
        "password_spray",
    ])

    data = json.loads(output_file.read_text(encoding="utf-8"))

    # If there are no matching incidents, the CLI will have printed a message
    # and not created the file, but in normal fixture logs we expect at least one.
    # So here we assert basic shape and that the pattern filter held.
    assert "incident" in data
    inc = data["incident"]
    assert inc["incident_id"].startswith("ip:")
    assert inc["severity"] in {"high", "medium", "low"}
    assert inc["attack_pattern"] == "password_spray"
    assert inc["priority"] in {"low", "medium", "high", "critical"}
    assert isinstance(inc["priority_score"], int)
    assert isinstance(inc["priority_reason"], str) and inc["priority_reason"]


def test_explain_ssh_json_output_with_threshold_percentile(tmp_path):
    output_file = tmp_path / "explain_threshold.json"

    main([
        "explain",
        "data/loghub/SSH.log",
        "--log-type",
        "ssh_auth",
        "--model-path",
        "models/log_anomaly_iforest_ssh.joblib",
        "--threshold-percentile",
        "95.0",
        "--first",
        "--format",
        "json",
        "--output",
        str(output_file),
    ])

    payload = json.loads(output_file.read_text(encoding="utf-8"))

    assert isinstance(payload, dict)
    assert "incident" in payload
    assert "summary" in payload
    assert "local_explanation" in payload
    assert "llm_prompt" in payload