from datetime import datetime
from pathlib import Path

from aegislog.parsing.apache_error import (
    parse_error_line,
    parse_error_file,
    TIME_FORMAT,
)
from aegislog.features.sessions import LogEvent


EXAMPLE_LINE = "[Thu Jun 09 06:07:04 2005] [notice] LDAP: Built with OpenLDAP LDAP SDK\n"


def test_parse_error_line_parses_timestamp_level_and_message():
    ev = parse_error_line(EXAMPLE_LINE)

    assert isinstance(ev, LogEvent)

    expected_ts = datetime.strptime("Thu Jun 09 06:07:04 2005", TIME_FORMAT)
    assert ev.timestamp == expected_ts

    # level is stored in user_agent for now
    assert ev.user_agent == "notice"

    assert ev.raw == EXAMPLE_LINE.rstrip("\n")
    assert ev.source == "apache_error"

    # Apache error logs do not have these fields
    assert ev.ip is None
    assert ev.user is None
    assert ev.method is None
    assert ev.path is None
    assert ev.status is None


def test_parse_error_line_ignores_empty_and_invalid_lines():
    assert parse_error_line("") is None
    assert parse_error_line("\n") is None

    bad_line = "this is not an apache error log line"
    assert parse_error_line(bad_line) is None


def test_parse_error_file_reads_multiple_valid_lines(tmp_path: Path):
    content = (
        "[Thu Jun 09 06:07:04 2005] [notice] first message\n"
        "[Thu Jun 09 06:08:05 2005] [error] second message\n"
        "this is not valid and should be ignored\n"
    )

    log_path = tmp_path / "apache_error.log"
    log_path.write_text(content, encoding="utf-8")

    events = parse_error_file(str(log_path))

    assert len(events) == 2

    ev1, ev2 = events

    assert ev1.user_agent == "notice"
    assert ev1.raw.endswith("first message")

    assert ev2.user_agent == "error"
    assert ev2.raw.endswith("second message")

    assert all(ev.source == "apache_error" for ev in events)