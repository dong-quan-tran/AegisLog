import re
from datetime import datetime

from aegislog.normalized import NormalizedEvent

_SYSLOG_RE = re.compile(
    r"^(?:<(?P<pri>\d+)>)?"
    r"(?P<timestamp>[A-Z][a-z]{2}\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<message>.*)$"
)

_SEVERITY_BY_CODE = {
    0: "emerg",
    1: "alert",
    2: "crit",
    3: "error",
    4: "warning",
    5: "notice",
    6: "info",
    7: "debug",
}


def _parse_timestamp(value: str):
    current_year = datetime.now().year
    return datetime.strptime(f"{current_year} {value}", "%Y %b %d %H:%M:%S")


def parse_syslog_line(line: str) -> NormalizedEvent | None:
    text = line.strip()
    if not text:
        return None

    match = _SYSLOG_RE.match(text)
    if not match:
        return None

    pri_text = match.group("pri")
    pri = int(pri_text) if pri_text is not None else None
    severity = None
    facility = None

    if pri is not None:
        facility = pri // 8
        severity_code = pri % 8
        severity = _SEVERITY_BY_CODE.get(severity_code)

    message = match.group("message")
    process_name = None

    if ":" in message:
        prefix, remainder = message.split(":", 1)
        cleaned_prefix = prefix.strip()
        if cleaned_prefix:
            process_name = cleaned_prefix
        message = remainder.strip()

    event = NormalizedEvent.from_mapping(
        {
            "timestamp": _parse_timestamp(match.group("timestamp")).isoformat(),
            "host": match.group("host"),
            "message": message,
            "severity": severity,
            "service": process_name,
            "facility": facility,
        }
    )
    return event


def parse_syslog_file(path: str) -> tuple[list[NormalizedEvent], list[str]]:
    events: list[NormalizedEvent] = []
    errors: list[str] = []

    with open(path, "r", encoding="utf-8") as f:
        for line_number, raw_line in enumerate(f, start=1):
            event = parse_syslog_line(raw_line)
            if event is None:
                if raw_line.strip():
                    errors.append(f"line {line_number}: could not parse syslog line")
                continue
            events.append(event)

    return events, errors