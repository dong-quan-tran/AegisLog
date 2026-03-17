import re
from datetime import datetime
from typing import List, Optional

from aegislog.features.sessions import LogEvent

# Example line:
# Dec 10 06:55:46 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

LINE_RE = re.compile(
    r"^(?P<month>\w{3})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>\S+):\s+"
    r"(?P<message>.*)$"
)

IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
USER_RE = re.compile(r"user (\S+)")
FAILED_RE = re.compile(r"Failed password")
ACCEPTED_RE = re.compile(r"Accepted password")


def _parse_timestamp(month: str, day: str, time_str: str, year: int = 2005) -> datetime:
    # Loghub SSH doesn’t always contain the year; we assume a fixed year (e.g., 2005)
    # for ordering within this dataset.
    month_num = MONTHS[month]
    hour, minute, second = map(int, time_str.split(":"))
    return datetime(year, month_num, int(day), hour, minute, second)


def parse_ssh_line(line: str, year: int = 2005) -> Optional[LogEvent]:
    line = line.rstrip("\n")
    if not line:
        return None
    m = LINE_RE.match(line)
    if not m:
        return None

    ts = _parse_timestamp(m.group("month"), m.group("day"), m.group("time"), year)
    message = m.group("message")

    # Extract IP (if present)
    ip_match = IP_RE.search(message)
    ip = ip_match.group(1) if ip_match else None

    # Extract username (if present)
    user_match = USER_RE.search(message)
    user = user_match.group(1) if user_match else None

    # Determine a simple "status" code for auth outcome
    if FAILED_RE.search(message):
        status = 401  # failed auth
    elif ACCEPTED_RE.search(message):
        status = 200  # successful auth
    else:
        status = None

    return LogEvent(
        timestamp=ts,
        ip=ip,
        user=user,
        method=None,
        path=None,
        status=status,
        user_agent=None,
        raw=line,
        source="ssh_auth",
    )


def parse_ssh_file(path: str, year: int = 2005) -> List[LogEvent]:
    events: List[LogEvent] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            ev = parse_ssh_line(line, year=year)
            if ev:
                events.append(ev)
    return events
