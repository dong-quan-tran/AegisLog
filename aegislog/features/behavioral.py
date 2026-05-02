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


def _compute_status_streak_max(statuses: list[int], predicate) -> int:
    streak = 0
    max_streak = 0
    for s in statuses:
        if predicate(s):
            streak += 1
            if streak > max_streak:
                max_streak = streak
        else:
            streak = 0
    return max_streak


def _compute_success_after_failure_count(statuses: list[int]) -> int:
    """
    Count how many successful auths (200) occur after at least
    one failed auth (401) in the session.
    """
    saw_failure = False
    count = 0
    for s in statuses:
        if s == 401:
            saw_failure = True
        elif s == 200 and saw_failure:
            count += 1
    return count


def _compute_burst_max_per_minute(timestamps) -> int:
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


def _compute_filtered_burst_max_per_minute(events, predicate) -> int:
    filtered_ts = [e.timestamp for e in events if predicate(e)]
    if not filtered_ts:
        return 0
    return _compute_burst_max_per_minute(pd.to_datetime(filtered_ts))


def _compute_inter_event_gaps_seconds(timestamps) -> tuple[float, float]:
    """
    Return (mean_gap_seconds, max_gap_seconds) for consecutive events
    within a session. If fewer than 2 events, both are 0.0.
    """
    if timestamps is None or len(timestamps) < 2:
        return 0.0, 0.0
    diffs = [
        (timestamps[i] - timestamps[i - 1]).total_seconds()
        for i in range(1, len(timestamps))
    ]
    if not diffs:
        return 0.0, 0.0
    mean_gap = float(sum(diffs) / len(diffs))
    max_gap = float(max(diffs))
    return mean_gap, max_gap


def _compute_rare_hour_flag(timestamps) -> int:
    if timestamps is None or len(timestamps) == 0:
        return 0
    hours = [ts.hour for ts in timestamps]
    rare_count = sum(1 for h in hours if 0 <= h < 4)
    return 1 if rare_count > len(hours) / 2 else 0


def sessions_to_features(sessions: List[Session]) -> pd.DataFrame:
    rows = []

    ip_first_seen: dict[str, float] = {}
    user_first_seen: dict[str, float] = {}

    all_paths = Counter()
    all_error_messages = Counter()

    for s in sessions:
        if s.ip:
            ts = s.start_time.timestamp()
            ip_first_seen[s.ip] = min(ip_first_seen.get(s.ip, ts), ts)
        if s.user:
            ts = s.start_time.timestamp()
            user_first_seen[s.user] = min(user_first_seen.get(s.user, ts), ts)

        for ev in s.events:
            if ev.path:
                all_paths[ev.path] += 1
            if getattr(ev, "message", None):
                all_error_messages[ev.message] += 1

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

        timestamps = [e.timestamp for e in events]
        pd_ts = pd.to_datetime(timestamps)

        # --- SSH-focused features ---
        auth_failed_streak_max = _compute_auth_failed_streak_max(statuses)
        success_after_failure_count = _compute_success_after_failure_count(statuses)
        auth_burst_max_per_minute = _compute_burst_max_per_minute(pd_ts)
        mean_gap_seconds, max_gap_seconds = _compute_inter_event_gaps_seconds(timestamps)

        ssh_distinct_users = len({ev.user for ev in events if ev.user})
        ssh_distinct_ips_per_user = len(
            {(ev.user, ev.ip) for ev in events if ev.user and ev.ip}
        )
        ssh_distinct_targeted_users = ssh_distinct_users
        ssh_rare_hour = _compute_rare_hour_flag(pd_ts)

        first_seen_ip_flag = 0
        first_seen_user_flag = 0
        if s.ip:
            first_seen_ip_flag = 1 if s.start_time.timestamp() == ip_first_seen.get(s.ip) else 0
        if s.user:
            first_seen_user_flag = 1 if s.start_time.timestamp() == user_first_seen.get(s.user) else 0

        # --- Apache-focused features ---
        apache_5xx_streak_max = _compute_status_streak_max(
            statuses,
            lambda s: s is not None and 500 <= s < 600,
        )
        apache_404_burst_max_per_minute = _compute_filtered_burst_max_per_minute(
            events,
            lambda e: e.status == 404,
        )
        apache_5xx_burst_max_per_minute = _compute_filtered_burst_max_per_minute(
            events,
            lambda e: e.status is not None and 500 <= e.status < 600,
        )
        apache_distinct_paths = len({ev.path for ev in events if ev.path})

        path_events = [ev.path for ev in events if ev.path]
        rare_path_count = sum(1 for p in path_events if all_paths[p] == 1)
        apache_rare_path_ratio = rare_path_count / len(path_events) if path_events else 0.0

        session_messages = [getattr(ev, "message", None) for ev in events if getattr(ev, "message", None)]
        rare_error_message_count = sum(
            1 for msg in session_messages if all_error_messages[msg] == 1
        )
        apache_rare_error_message_ratio = (
            rare_error_message_count / len(session_messages) if session_messages else 0.0
        )

        apache_rare_hour = _compute_rare_hour_flag(pd_ts)
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
                # SSH feature columns
                "auth_failed_streak_max": auth_failed_streak_max,
                "success_after_failure_count": success_after_failure_count,
                "auth_burst_max_per_minute": auth_burst_max_per_minute,
                "mean_inter_event_gap_seconds": mean_gap_seconds,
                "max_inter_event_gap_seconds": max_gap_seconds,
                "ssh_distinct_users": ssh_distinct_users,
                "ssh_distinct_ips_per_user": ssh_distinct_ips_per_user,
                "ssh_distinct_targeted_users": ssh_distinct_targeted_users,
                "ssh_rare_hour": ssh_rare_hour,
                "first_seen_ip_flag": first_seen_ip_flag,
                "first_seen_user_flag": first_seen_user_flag,
                # Apache feature columns
                "apache_5xx_streak_max": apache_5xx_streak_max,
                "apache_404_burst_max_per_minute": apache_404_burst_max_per_minute,
                "apache_5xx_burst_max_per_minute": apache_5xx_burst_max_per_minute,
                "apache_distinct_paths": apache_distinct_paths,
                "apache_rare_path_ratio": apache_rare_path_ratio,
                "apache_rare_error_message_ratio": apache_rare_error_message_ratio,
                "apache_rare_hour": apache_rare_hour,
            }
        )
    return pd.DataFrame(rows)