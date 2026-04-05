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

        # Existing error-level features for apache_error (from user_agent)
        levels = [e.user_agent for e in events if e.user_agent is not None]
        level_counts = Counter(levels)
        error_events = level_counts.get("error", 0)
        notice_events = level_counts.get("notice", 0)
        error_event_ratio = error_events / total if total else 0.0

        # SSH auth features based on status codes
        auth_failed = sum(1 for c in statuses if c == 401)
        auth_success = sum(1 for c in statuses if c == 200)
        auth_total = auth_failed + auth_success
        auth_fail_ratio = auth_failed / auth_total if auth_total else 0.0

        avg_events_per_second = total / max(duration, 1)
        unique_paths = len({ev.path for ev in s.events if ev.path})

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
                "auth_failed": auth_failed,
                "auth_success": auth_success,
                "auth_fail_ratio": auth_fail_ratio,
                "avg_events_per_second": avg_events_per_second,
                "unique_paths": unique_paths,
            }
        )
    return pd.DataFrame(rows)