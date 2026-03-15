import re
from datetime import datetime, timezone
from typing import Iterable, List

from aegislog.features.sessions import LogEvent  # <- correct import

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) \S+ ".*" "(?P<ua>.*)"'
)

TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

def parse_access_line(line: str) -> LogEvent | None:
    m = LOG_PATTERN.match(line)
    if not m:
        return None
    ts = datetime.strptime(m.group("time"), TIME_FORMAT).astimezone(timezone.utc)
    return LogEvent(
        timestamp=ts,
        ip=m.group("ip"),
        user=None,
        method=m.group("method"),
        path=m.group("path"),
        status=int(m.group("status")),
        user_agent=m.group("ua") or None,
        raw=line.rstrip("\n"),
        source="access",
    )

def parse_access_file(path: str) -> list[LogEvent]:
    events: list[LogEvent] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            ev = parse_access_line(line)
            if ev:
                events.append(ev)
    return events
