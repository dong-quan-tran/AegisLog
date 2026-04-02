import json
from datetime import datetime
from types import SimpleNamespace

from aegislog.cli import write_output, session_row_to_dict, incident_to_dict


def test_write_output_writes_file(tmp_path):
    output_file = tmp_path / "out.json"
    write_output('{"ok": true}', str(output_file))
    assert output_file.read_text(encoding="utf-8") == '{"ok": true}\n'


def test_session_row_to_dict_converts_nan_to_none():
    nan = float("nan")
    row = {
        "session_id": "1.2.3.4||1",
        "ip": "1.2.3.4",
        "user": nan,
        "event_count": 12,
        "error_ratio": 0.5,
        "anomaly_score": 0.123,
    }

    data = session_row_to_dict(row)

    assert data == {
        "session_id": "1.2.3.4||1",
        "ip": "1.2.3.4",
        "user": None,
        "event_count": 12,
        "error_ratio": 0.5,
        "anomaly_score": 0.123,
    }


def test_incident_to_dict_returns_expected_shape():
    inc = SimpleNamespace(
        incident_id="ip:1.2.3.4#1",
        ip="1.2.3.4",
        severity="high",
        session_ids=["1.2.3.4||1"],
        total_events=12,
        avg_anomaly_score=0.123,
        auth_failed=10,
        auth_success=0,
        auth_fail_ratio=1.0,
        first_seen=datetime(2025, 1, 1, 12, 0, 0),
        last_seen=datetime(2025, 1, 1, 12, 30, 0),
    )
    summary = SimpleNamespace(
        title="Test incident",
        description="Test description",
    )
    llm_prompt = SimpleNamespace(
        prompt="Explain this incident.",
    )

    data = incident_to_dict(
        inc,
        summary,
        "Local explanation text",
        llm_prompt,
    )

    assert data["incident"]["incident_id"] == "ip:1.2.3.4#1"
    assert data["incident"]["ip"] == "1.2.3.4"
    assert data["summary"]["title"] == "Test incident"
    assert data["local_explanation"] == "Local explanation text"
    assert data["llm_prompt"] == "Explain this incident"