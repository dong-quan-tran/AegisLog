import json

from aegislog.normalized_loader import load_normalized_events


def test_load_normalized_events_generic_with_mapping_file(tmp_path):
    log_path = tmp_path / "events.jsonl"
    mapping_path = tmp_path / "mapping.json"

    log_path.write_text(
        json.dumps(
            {
                "ts": "2025-01-15T12:34:56",
                "client_ip": "203.0.113.10",
                "user_name": "alice",
                "status": 401,
                "log_message": "failed login",
                "level": "warning",
            }
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

    events, errors = load_normalized_events(
        source_type="generic",
        path=str(log_path),
        input_format="jsonl",
        mapping_path=str(mapping_path),
    )

    assert errors == []
    assert len(events) == 1

    event = events[0]
    assert event.src_ip == "203.0.113.10"
    assert event.user == "alice"
    assert event.status_code == 401
    assert event.message == "failed login"
    assert event.severity == "warning"