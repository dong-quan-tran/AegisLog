from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, List, Optional


@dataclass
class LogEvent:
    timestamp: datetime
    ip: Optional[str]
    user: Optional[str]
    method: Optional[str]
    path: Optional[str]
    status: Optional[int]
    user_agent: Optional[str]
    raw: str
    source: str  # "access" | "auth" | ...


@dataclass
class Session:
    session_id: str
    ip: Optional[str]
    user: Optional[str]
    user_agent: Optional[str]
    events: List[LogEvent]
    start_time: datetime
    end_time: datetime
    source_set: set[str]


def build_sessions(events: Iterable[LogEvent], gap_minutes: int = 30) -> list[Session]:
    events_sorted = sorted(
        events,
        key=lambda e: (e.ip or "", e.user or "", e.user_agent or "", e.timestamp),
    )

    sessions: list[Session] = []
    current: list[LogEvent] = []
    current_key: tuple[str, str, str] | None = None
    last_ts: datetime | None = None
    gap = timedelta(minutes=gap_minutes)

    def flush_session():
        nonlocal current, current_key
        if not current or current_key is None:
            return
        ip, user, ua = current_key
        session_id = f"{ip or ''}||{user or ''}||{current[0].timestamp.isoformat()}"
        sessions.append(Session(
            session_id=session_id,
            ip=ip or None,
            user=user or None,
            user_agent=ua or None,
            events=current,
            start_time=current[0].timestamp,
            end_time=current[-1].timestamp,
            source_set={ev.source for ev in current if ev.source},
        ))
        current = []
        current_key = None

    for ev in events_sorted:
        key = (ev.ip or "", ev.user or "", ev.user_agent or "")
        if current_key is None:
            current_key = key
            current = [ev]
            last_ts = ev.timestamp
            continue

        if key != current_key or (last_ts and ev.timestamp - last_ts > gap):
            flush_session()
            current_key = key
            current = [ev]
        else:
            current.append(ev)
        last_ts = ev.timestamp

    flush_session()
    return sessions