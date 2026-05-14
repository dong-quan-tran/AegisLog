from datetime import datetime
from pathlib import Path

from aegislog.features.sessions import LogEvent
from aegislog.parsing.apache_error import TIME_FORMAT, parse_error_file, parse_error_line

EXAMPLE_LINE = "[Thu Jun 09 06:07:04 2005] [notice] LDAP: Built with OpenLDAP LDAP SDK"


def test_parse_error_line_parses_timestamp_level_and_message():
    ev = parse_error_line(EXAMPLE_LINE)

    assert isinstance(ev, LogEvent)

    expected_ts = datetime.strptime("Thu Jun 09 06:07:04 2005", TIME_FORMAT)
    assert ev.timestamp == expected_ts

    assert getattr(ev, "level", None) == "notice"
    assert getattr(ev, "message", None) == "LDAP: Built with OpenLDAP LDAP SDK"

    assert ev.raw == EXAMPLE_LINE
    assert ev.source == "apache_error"
    assert ev.user_agent is None


def test_parse_error_line_returns_none_for_invalid_line():
    assert parse_error_line("") is None
    assert parse_error_line("not a valid apache error line") is None


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

    assert getattr(ev1, "level", None) == "notice"
    assert getattr(ev1, "message", None) == "first message"
    assert ev1.user_agent is None

    assert getattr(ev2, "level", None) == "error"
    assert getattr(ev2, "message", None) == "second message"
    assert ev2.user_agent is None