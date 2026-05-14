from datetime import datetime

from aegislog.adapters.apache import apache_record_to_normalized_event


class DummyApacheRecord:
    def __init__(
        self,
        *,
        raw: str,
        timestamp,
        level=None,
        source="apache_error",
    ):
        self.raw = raw
        self.timestamp = timestamp
        self.level = level
        self.source = source


def test_apache_missing_file_normalizes_expected_fields() -> None:
    record = DummyApacheRecord(
        raw='[error] [client 203.0.113.50] File does not exist: /var/www/favicon.ico',
        timestamp=datetime(2026, 5, 13, 13, 0, 0),
        level="error",
    )

    event = apache_record_to_normalized_event(record)

    assert event.timestamp == "2026-05-13T13:00:00"
    assert event.source_type == "apache"
    assert event.event_category == "application"
    assert event.event_action == "missing_file"
    assert event.severity == "error"
    assert event.service == "apache"
    assert event.session_hint is None
    assert event.extra["apache_level"] == "error"
    assert event.extra["parser_source"] == "apache_error"


def test_apache_notice_resuming_operations_maps_to_service_start() -> None:
    record = DummyApacheRecord(
        raw="Apache/2.0.52 (CentOS) configured -- resuming normal operations",
        timestamp="2026-05-13T13:05:00",
        level="notice",
    )

    event = apache_record_to_normalized_event(record)

    assert event.timestamp == "2026-05-13T13:05:00"
    assert event.source_type == "apache"
    assert event.event_action == "service_start"
    assert event.severity == "info"
    assert event.service == "apache"
    assert event.extra["apache_level"] == "notice"
    assert event.extra["parser_source"] == "apache_error"