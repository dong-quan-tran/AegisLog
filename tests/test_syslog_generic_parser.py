from aegislog.parsing.syslog_generic import parse_syslog_file, parse_syslog_line


def test_parse_syslog_line_with_pri():
    line = "<34>Oct 11 22:14:15 myhost su: failed login for root"
    event = parse_syslog_line(line)

    assert event is not None
    assert event.host == "myhost"
    assert event.service == "su"
    assert event.message == "failed login for root"
    assert event.severity == "crit"


def test_parse_syslog_line_without_pri():
    line = "Oct 11 22:14:15 myhost sshd[1234]: Accepted password for alice"
    event = parse_syslog_line(line)

    assert event is not None
    assert event.host == "myhost"
    assert event.service == "sshd[1234]"
    assert event.message == "Accepted password for alice"


def test_parse_syslog_file_collects_errors(tmp_path):
    log_path = tmp_path / "sample.log"
    log_path.write_text(
        "Oct 11 22:14:15 myhost sshd[1234]: Accepted password for alice\n"
        "not a syslog line\n"
        "<34>Oct 11 22:14:16 myhost su: failed login for root\n",
        encoding="utf-8",
    )

    events, errors = parse_syslog_file(str(log_path))

    assert len(events) == 2
    assert len(errors) == 1
    assert "line 2" in errors[0]