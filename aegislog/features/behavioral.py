import pandas as pd
from typing import List
from collections import Counter
from .sessions import Session


def _compute_auth_failed_streak_max(statuses: list[int]) -> int:
    streak = 0
    max_streak = 0
    for s in statuses:
        if s == 401:
            streak += 1
            if streak > max_streak:
                max_streak = streak
        else:
            streak = 0
    return max_streak


def _compute_burst_max_per_minute(timestamps) -> int:
    # timestamps is expected to be a sequence/Index of pandas Timestamps
    if timestamps is None or len(timestamps) == 0:
        return 0
    left = 0
    max_count = 1
    for right in range(len(timestamps)):
        while timestamps[right] - timestamps[left] > pd.Timedelta(seconds=60):
            left += 1
        window_size = right - left + 1
        if window_size > max_count:
            max_count = window_size
    return max_count


def _compute_rare_hour_flag(timestamps) -> int:
    if timestamps is None or len(timestamps) == 0:
        return 0
    hours = [ts.hour for ts in timestamps]
    rare_count = sum(1 for h in hours if 0 <= h < 4)
    return 1 if rare_count > len(hours) / 2 else 0


def sessions_to_features(sessions: List[Session]) -> pd.DataFrame:
    rows = []
    for s in sessions:
        events = s.events
        if not events:
            continue

        statuses = [e.status for e in events if e.status is not None]
        total = len(events)
        duration = (s.end_time - s.start_time).total_seconds()
        status_4xx = sum(1 for c in statuses if 400 <= c < 500)
        status_5xx = sum(1 for c in statuses if 500 <= c < 600)

        levels = [e.user_agent for e in events if e.user_agent is not None]
        level_counts = Counter(levels)
        error_events = level_counts.get("error", 0)
        notice_events = level_counts.get("notice", 0)
        error_event_ratio = error_events / total if total else 0.0

        auth_failed = sum(1 for c in statuses if c == 401)
        auth_success = sum(1 for c in statuses if c == 200)
        auth_total = auth_failed + auth_success
        auth_fail_ratio = auth_failed / auth_total if auth_total else 0.0

        avg_events_per_second = total / max(duration, 1)
        unique_paths = len({ev.path for ev in s.events if ev.path})
        source_count = len(s.source_set)
        has_mixed_sources = 1 if len(s.source_set) > 1 else 0

        # --- NEW SSH-focused features ---
        timestamps = [e.timestamp for e in events]
        auth_failed_streak_max = _compute_auth_failed_streak_max(statuses)
        auth_burst_max_per_minute = _compute_burst_max_per_minute(
            pd.to_datetime(timestamps)
        )
        ssh_distinct_users = len({ev.user for ev in events if ev.user})
        ssh_distinct_ips_per_user = len({(ev.user, ev.ip) for ev in events if ev.user and ev.ip})
        ssh_rare_hour = _compute_rare_hour_flag(pd.to_datetime(timestamps))
        # --------------------------------

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
                "source_count": source_count,
                "has_mixed_sources": has_mixed_sources,
                # NEW feature columns
                "auth_failed_streak_max": auth_failed_streak_max,
                "auth_burst_max_per_minute": auth_burst_max_per_minute,
                "ssh_distinct_users": ssh_distinct_users,
                "ssh_distinct_ips_per_user": ssh_distinct_ips_per_user,
                "ssh_rare_hour": ssh_rare_hour,
            }
        )
    return pd.DataFrame(rows)