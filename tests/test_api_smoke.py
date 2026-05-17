from fastapi.testclient import TestClient

from aegislog.api import app

client = TestClient(app)

SAMPLE_GENERIC_JSONL = """{"timestamp":"2026-05-16T10:00:00Z","message":"login failed","severity":"warn","user":"alice","src_ip":"10.0.0.1","event_category":"auth","event_action":"login_failed"}
{"timestamp":"2026-05-16T10:03:00Z","message":"login failed","severity":"warn","user":"alice","src_ip":"10.0.0.1","event_category":"auth","event_action":"login_failed"}
{"timestamp":"2026-05-16T10:20:00Z","message":"login ok","severity":"info","user":"alice","src_ip":"10.0.0.1","event_category":"auth","event_action":"login_success"}"""

SAMPLE_SYSLOG = """Jan 16 10:00:00 app01 sshd[1234]: Failed password for invalid user admin from 10.0.0.9 port 22 ssh2
Jan 16 10:02:00 app01 sshd[1235]: Failed password for invalid user admin from 10.0.0.9 port 22 ssh2
Jan 16 10:10:00 app01 sshd[1236]: Accepted password for alice from 10.0.0.9 port 22 ssh2"""


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_normalize_generic_jsonl():
    response = client.post(
        "/normalize",
        json={
            "content": SAMPLE_GENERIC_JSONL,
            "source_type": "generic",
            "input_format": "jsonl",
            "top": 2,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["source_type"] == "generic"
    assert body["input_format"] == "jsonl"
    assert body["summary"]["total_events"] == 3
    assert len(body["preview"]) == 2


def test_generic_incidents():
    response = client.post(
        "/generic-incidents",
        json={
            "content": SAMPLE_GENERIC_JSONL,
            "source_type": "generic",
            "input_format": "jsonl",
            "window_minutes": 15,
            "top": 5,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["source_type"] == "generic"
    assert body["total_events"] == 3
    assert body["total_incidents"] >= 1
    assert isinstance(body["incidents"], list)


def test_normalized_incidents_generic():
    response = client.post(
        "/normalized-incidents",
        json={
            "content": SAMPLE_GENERIC_JSONL,
            "source_type": "generic",
            "input_format": "jsonl",
            "window_minutes": 15,
            "top": 5,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["source_type"] == "generic"
    assert body["total_events"] == 3
    assert "incidents" in body


def test_normalized_incidents_syslog_generic_source():
    response = client.post(
        "/normalized-incidents",
        json={
            "content": SAMPLE_SYSLOG,
            "source_type": "generic",
            "input_format": "syslog",
            "window_minutes": 15,
            "top": 5,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["source_type"] == "generic"
    assert body["input_format"] == "syslog"
    assert body["total_events"] == 3


def test_generic_explain_first():
    response = client.post(
        "/generic-explain",
        json={
            "content": SAMPLE_GENERIC_JSONL,
            "source_type": "generic",
            "input_format": "jsonl",
            "window_minutes": 15,
            "first": True,
            "use_ai": False,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["source_type"] == "generic"
    assert "incident" in body
    assert "incident_evidence" in body


def test_normalized_explain_first():
    response = client.post(
        "/normalized-explain",
        json={
            "content": SAMPLE_GENERIC_JSONL,
            "source_type": "generic",
            "input_format": "jsonl",
            "window_minutes": 15,
            "first": True,
            "use_ai": False,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["source_type"] == "generic"
    assert "incident" in body
    assert "incident_evidence" in body


def test_mapping_rejected_for_non_generic_source():
    response = client.post(
        "/normalize",
        json={
            "content": SAMPLE_GENERIC_JSONL,
            "source_type": "ssh",
            "input_format": "jsonl",
            "mapping": {"fields": {"message": ["msg"]}},
        },
    )
    assert response.status_code == 422