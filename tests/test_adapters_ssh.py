from datetime import datetime

from aegislog.adapters.ssh import ssh_record_to_normalized_event


class DummySSHRecord:
    def __init__(
        self,
        *,
        raw: str,
        timestamp,
        ip=None,
        user=None,
        status=None,
        source="ssh_auth",
        method=None,
        path=None,
        user_agent=None,
    ):
        self.raw = raw
        self.timestamp = timestamp
        self.ip = ip
        self.user = user
        self.status = status
        self.source = source
        self.method = method
        self.path = path
        self.user_agent = user_agent


def test_ssh_failed_password_normalizes_expected_fields() -> None:
    record = DummySSHRecord(
        raw="Failed password for invalid user admin from 203.0.113.10 port 22 ssh2",
        timestamp=datetime(2026, 5, 13, 12, 0, 0),
        ip="203.0.113.10",
        user="admin",
        status=401,
    )

    event = ssh_record_to_normalized_event(record)

    assert event.timestamp == "2026-05-13T12:00:00"
    assert event.source_type == "ssh"
    assert event.event_category == "auth"
    assert event.event_action == "login_failed"
    assert event.severity == "warn"
    assert event.src_ip == "203.0.113.10"
    assert event.user == "admin"
    assert event.service == "ssh"
    assert event.status_code == 401
    assert event.session_hint == "203.0.113.10|admin"
    assert event.extra == {}


def test_ssh_accepts_publickey_as_login_success() -> None:
    record = DummySSHRecord(
        raw="Accepted publickey for deploy from 198.51.100.7 port 22 ssh2",
        timestamp="2026-05-13T12:30:00",
        ip="198.51.100.7",
        user="deploy",
        status=200,
        method="GET",
        path="/ignored",
        user_agent="ssh-client",
    )

    event = ssh_record_to_normalized_event(record)

    assert event.timestamp == "2026-05-13T12:30:00"
    assert event.source_type == "ssh"
    assert event.event_action == "login_success"
    assert event.severity == "info"
    assert event.src_ip == "198.51.100.7"
    assert event.user == "deploy"
    assert event.session_hint == "198.51.100.7|deploy"
    assert event.extra["method"] == "GET"
    assert event.extra["path"] == "/ignored"
    assert event.extra["user_agent"] == "ssh-client"