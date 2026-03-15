import pandas as pd
from typing import List
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
            }
        )
    return pd.DataFrame(rows)
