from aegislog.parsing.generic import load_generic_jsonl


def test_load_generic_jsonl_applies_mapping(tmp_path) -> None:
    path = tmp_path / "mapped.jsonl"
    path.write_text(
        "\n".join(
            [
                '{"@timestamp":"2026-05-13T12:00:00Z","msg":"login failed","level":"warn","client_ip":"203.0.113.5","username":"alice","app":"auth-service","event_type":"login_failed","request_id":"req-123"}',
                '{"@timestamp":"2026-05-13T12:01:00Z","msg":"db timeout","level":"error","hostname":"web-01","application":"orders","category":"application","action":"timeout","status":"504"}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    mapping = {
        "source_type": "generic_jsonl",
        "fields": {
            "timestamp": ["@timestamp"],
            "message": ["msg"],
            "severity": ["level"],
            "src_ip": ["client_ip"],
            "user": ["username"],
            "service": ["app", "application"],
            "event_action": ["event_type", "action"],
            "event_category": ["category"],
            "status_code": ["status"],
            "session_hint": ["request_id"],
            "host": ["hostname"],
        },
    }

    events, errors = load_generic_jsonl(str(path), mapping=mapping)

    assert errors == []
    assert len(events) == 2

    first = events[0]
    assert first.timestamp == "2026-05-13T12:00:00+00:00"
    assert first.source_type == "generic_jsonl"
    assert first.message == "login failed"
    assert first.severity == "warn"
    assert first.src_ip == "203.0.113.5"
    assert first.user == "alice"
    assert first.service == "auth-service"
    assert first.event_action == "login_failed"
    assert first.session_hint == "req-123"

    second = events[1]
    assert second.timestamp == "2026-05-13T12:01:00+00:00"
    assert second.source_type == "generic_jsonl"
    assert second.message == "db timeout"
    assert second.severity == "error"
    assert second.host == "web-01"
    assert second.service == "orders"
    assert second.event_category == "application"
    assert second.event_action == "timeout"
    assert second.status_code == 504