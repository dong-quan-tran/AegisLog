import json

from aegislog.parsing.jsonl_generic import parse_jsonl_with_mapping


def test_parse_jsonl_with_mapping(tmp_path):
    log_path = tmp_path / "events.jsonl"
    mapping_path = tmp_path / "mapping.json"

    log_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "ts": "2025-01-15T12:34:56",
                        "client_ip": "203.0.113.10",
                        "user_name": "alice",
                        "status": 401,
                        "log_message": "failed login",
                        "level": "warning",
                    }
                ),
                json.dumps(
                    {
                        "ts": "2025-01-15T12:35:10",
                        "client_ip": "203.0.113.11",
                        "user_name": "bob",
                        "status": 200,
                        "log_message": "login success",
                        "level": "info",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    mapping_path.write_text(
        json.dumps(
            {
                "fields": {
                    "timestamp": "ts",
                    "src_ip": "client_ip",
                    "user": "user_name",
                    "status_code": "status",
                    "message": "log_message",
                    "severity": "level",
                }
            }
        ),
        encoding="utf-8",
    )

    events = parse_jsonl_with_mapping(str(log_path), str(mapping_path))

    assert len(events) == 2

    first = events[0]
    second = events[1]

    assert first.src_ip == "203.0.113.10"
    assert first.user == "alice"
    assert first.status_code == 401
    assert first.message == "failed login"
    assert first.severity == "warning"

    assert second.src_ip == "203.0.113.11"
    assert second.user == "bob"
    assert second.status_code == 200
    assert second.message == "login success"
    assert second.severity == "info"


def test_parse_jsonl_without_mapping_uses_record_directly(tmp_path):
    log_path = tmp_path / "events.jsonl"
    log_path.write_text(
        json.dumps(
            {
                "timestamp": "2025-01-15T12:34:56",
                "src_ip": "198.51.100.7",
                "user": "charlie",
                "status_code": 500,
                "message": "server error",
                "severity": "error",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    events = parse_jsonl_with_mapping(str(log_path), None)

    assert len(events) == 1
    event = events[0]

    assert event.src_ip == "198.51.100.7"
    assert event.user == "charlie"
    assert event.status_code == 500
    assert event.message == "server error"
    assert event.severity == "error"