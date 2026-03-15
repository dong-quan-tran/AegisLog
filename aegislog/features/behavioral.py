import pandas as pd
from typing import List
from collections import Counter
from .sessions import Session

def sessions_to_features(sessions: List[Session]) -> pd.DataFrame:
    rows = []
    for s in sessions:
        events = s.events
        if not events:
            continue

        statuses = [e.status for e in events if e.status is not None]
        total = len(events)
        duration = (events[-1].timestamp - events[0].timestamp).total_seconds()
        status_4xx = sum(1 for c in statuses if 400 <= c < 500)
        status_5xx = sum(1 for c in statuses if 500 <= c < 600)

        # derive log levels from user_agent (apache_error parser stores level there)
        levels = [e.user_agent for e in events if e.user_agent is not None]
        level_counts = Counter(levels)
        error_events = level_counts.get("error", 0)
        notice_events = level_counts.get("notice", 0)
        error_event_ratio = error_events / total if total else 0.0

        rows.append(
            {
                "session_id": s.session_id,
                "ip": s.ip,
                "user": s.user,
                "event_count": total,
                "duration_seconds": duration,
                "status_4xx": status_4xx,
                "status_5xx": status_5xx,
                "error_ratio": (status_4xx + status_5xx) / total if total else 0.0,
                "error_events": error_events,
                "notice_events": notice_events,
                "error_event_ratio": error_event_ratio,
            }
        )
    return pd.DataFrame(rows)
