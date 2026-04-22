import json

from aegislog.cli import main


def test_report_ssh_json_output(tmp_path):
    output_file = tmp_path / "report.json"

    main([
        "report",
        "data/loghub/SSH.log",
        "--log-type",
        "ssh_auth",
        "--model-path",
        "models/log_anomaly_iforest_ssh.joblib",
        "--format",
        "json",
        "--output",
        str(output_file),
    ])

    payload = json.loads(output_file.read_text(encoding="utf-8"))

    assert isinstance(payload, dict)

    expected_top_level_keys = {
        "total_sessions",
        "anomalous_sessions",
        "anomalous_session_percent",
        "total_incidents",
        "severity_counts",
        "confidence_counts",
        "priority_counts",
        "attack_pattern_counts",
        "top_incident_ips",
        "top_targeted_users",
    }
    assert expected_top_level_keys.issubset(payload.keys())

    assert isinstance(payload["total_sessions"], int)
    assert isinstance(payload["anomalous_sessions"], int)
    assert isinstance(payload["anomalous_session_percent"], (int, float))
    assert isinstance(payload["total_incidents"], int)

    assert isinstance(payload["severity_counts"], dict)
    assert isinstance(payload["confidence_counts"], dict)
    assert isinstance(payload["priority_counts"], dict)
    assert isinstance(payload["attack_pattern_counts"], dict)

    assert isinstance(payload["top_incident_ips"], list)
    assert isinstance(payload["top_targeted_users"], list)


def test_report_ssh_json_output_filtered_by_pattern(tmp_path):
    output_file = tmp_path / "report_pattern.json"

    main([
        "report",
        "data/loghub/SSH.log",
        "--log-type",
        "ssh_auth",
        "--model-path",
        "models/log_anomaly_iforest_ssh.joblib",
        "--format",
        "json",
        "--output",
        str(output_file),
        "--pattern",
        "password_spray",
    ])

    payload = json.loads(output_file.read_text(encoding="utf-8"))

    assert isinstance(payload, dict)

    expected_top_level_keys = {
        "total_sessions",
        "anomalous_sessions",
        "anomalous_session_percent",
        "total_incidents",
        "severity_counts",
        "confidence_counts",
        "priority_counts",
        "attack_pattern_counts",
        "top_incident_ips",
        "top_targeted_users",
    }
    assert expected_top_level_keys.issubset(payload.keys())

    attack_pattern_counts = payload["attack_pattern_counts"]
    assert isinstance(attack_pattern_counts, dict)

    nonzero_patterns = {
        pattern: count
        for pattern, count in attack_pattern_counts.items()
        if count > 0
    }

    if payload["total_incidents"] > 0:
        assert set(nonzero_patterns.keys()) == {"password_spray"}
        assert nonzero_patterns["password_spray"] == payload["total_incidents"]


def test_report_ssh_json_output_filtered_by_severity_confidence_and_pattern(tmp_path):
    output_file = tmp_path / "report_filtered.json"

    main([
        "report",
        "data/loghub/SSH.log",
        "--log-type",
        "ssh_auth",
        "--model-path",
        "models/log_anomaly_iforest_ssh.joblib",
        "--format",
        "json",
        "--output",
        str(output_file),
        "--min-severity",
        "medium",
        "--min-confidence",
        "medium",
        "--pattern",
        "password_spray",
    ])

    payload = json.loads(output_file.read_text(encoding="utf-8"))

    assert isinstance(payload, dict)

    expected_top_level_keys = {
        "total_sessions",
        "anomalous_sessions",
        "anomalous_session_percent",
        "total_incidents",
        "severity_counts",
        "confidence_counts",
        "priority_counts",
        "attack_pattern_counts",
        "top_incident_ips",
        "top_targeted_users",
    }
    assert expected_top_level_keys.issubset(payload.keys())

    if payload["total_incidents"] > 0:
        nonzero_severities = {
            severity: count
            for severity, count in payload["severity_counts"].items()
            if count > 0
        }
        assert set(nonzero_severities.keys()).issubset({"medium", "high"})

        nonzero_confidences = {
            confidence: count
            for confidence, count in payload["confidence_counts"].items()
            if count > 0
        }
        assert set(nonzero_confidences.keys()).issubset({"medium", "high"})

        nonzero_patterns = {
            pattern: count
            for pattern, count in payload["attack_pattern_counts"].items()
            if count > 0
        }
        assert set(nonzero_patterns.keys()) == {"password_spray"}