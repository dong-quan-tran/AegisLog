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


def test_incidents_ssh_json_output_filtered_by_pattern(tmp_path):
    output_file = tmp_path / "incidents_pattern.json"

    main([
        "incidents",
        "data/loghub/SSH.log",
        "--log-type",
        "ssh_auth",
        "--model-path",
        "models/log_anomaly_iforest_ssh.joblib",
        "--top",
        "10",
        "--format",
        "json",
        "--output",
        str(output_file),
        "--pattern",
        "password_spray",
    ])

    data = json.loads(output_file.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    # Depending on the fixture log, there might be zero matching incidents,
    # but if there are any, they must all match the requested pattern.
    if data:
        for item in data:
            inc = item["incident"]
            assert inc["attack_pattern"] == "password_spray"
            assert inc["priority"] in {"low", "medium", "high", "critical"}
            assert isinstance(inc["priority_score"], int)
            # priority_reason should be a non-empty string
            assert isinstance(inc["priority_reason"], str)
            assert inc["priority_reason"]