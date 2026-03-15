import re
from datetime import datetime
from typing import List

from aegislog.features.sessions import LogEvent

# Example line:
# [Thu Jun 09 06:07:04 2005] [notice] LDAP: Built with OpenLDAP LDAP SDK
LOG_PATTERN = re.compile(
    r"\[(?P<time>[^\]]+)\]\s+\[(?P<level>[^\]]+)\]\s+(?P<message>.*)"
)

TIME_FORMAT = "%a %b %d %H:%M:%S %Y"  # Thu Jun 09 06:07:04 2005

def parse_error_line(line: str) -> LogEvent | None:
    line = line.rstrip("\n")
    if not line:
        return None
    m = LOG_PATTERN.match(line)
    if not m:
        return None
    ts_str = m.group("time")
    ts = datetime.strptime(ts_str, TIME_FORMAT)

    # For error logs, we often don't have IP/user/path/status directly.
    # We'll treat the whole message as "path" or "user_agent"-like text.
    message = m.group("message")

    return LogEvent(
        timestamp=ts,
        ip=None,
        user=None,
        method=None,
        path=None,
        status=None,
        user_agent=None,
        raw=line,
        source="apache_error",
    )

def parse_error_file(path: str) -> List[LogEvent]:
    events: List[LogEvent] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            ev = parse_error_line(line)
            if ev:
                events.append(ev)
    return events
