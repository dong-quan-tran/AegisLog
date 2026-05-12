from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from aegislog.normalized import NormalizedEvent


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _safe_key(value: Optional[str]) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _guess_group_key(event: NormalizedEvent) -> str:
    if event.session_hint:
        return f"session_hint:{event.session_hint}"
    if event.src_ip and event.user:
        return f"src_ip_user:{event.src_ip}|{event.user}"
    if event.src_ip:
        return f"src_ip:{event.src_ip}"
    if event.user:
        return f"user:{event.user}"
    if event.host and event.service:
        return f"host_service:{event.host}|{event.service}"
    if event.host:
        return f"host:{event.host}"
    if event.service:
        return f"service:{event.service}"
    return "unknown"


@dataclass
class GenericIncident:
    incident_id: str
    group_key: str
    severity: str
    confidence: str
    priority: str
    attack_pattern: str
    event_count: int
    error_count: int
    warning_count: int
    distinct_users: int
    distinct_hosts: int
    distinct_src_ips: int
    first_seen: Optional[str]
    last_seen: Optional[str]
    source_type: str
    summary_title: str
    summary_description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "group_key": self.group_key,
            "severity": self.severity,
            "confidence": self.confidence,
            "priority": self.priority,
            "attack_pattern": self.attack_pattern,
            "event_count": self.event_count,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "distinct_users": self.distinct_users,
            "distinct_hosts": self.distinct_hosts,
            "distinct_src_ips": self.distinct_src_ips,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "source_type": self.source_type,
            "summary": {
                "title": self.summary_title,
                "description": self.summary_description,
            },
        }


def _window_bucket(ts: Optional[datetime], minutes: int) -> str:
    if ts is None:
        return "no_time"
    floored_minute = (ts.minute // minutes) * minutes
    bucket = ts.replace(minute=floored_minute, second=0, microsecond=0)
    return bucket.isoformat()


def group_generic_events_to_incidents(
    events: List[NormalizedEvent],
    *,
    window_minutes: int = 15,
) -> List[GenericIncident]:
    buckets: Dict[str, List[NormalizedEvent]] = defaultdict(list)

    for event in events:
        ts = _parse_dt(event.timestamp)
        group_key = _guess_group_key(event)
        bucket_key = _window_bucket(ts, window_minutes)
        buckets[f"{group_key}||{bucket_key}"].append(event)

    incidents: List[GenericIncident] = []

    for idx, (bucket_id, bucket_events) in enumerate(sorted(buckets.items()), start=1):
        timestamps = [_parse_dt(event.timestamp) for event in bucket_events]
        timestamps = [ts for ts in timestamps if ts is not None]

        first_seen = min(timestamps).isoformat() if timestamps else None
        last_seen = max(timestamps).isoformat() if timestamps else None

        users = sorted({_safe_key(event.user) for event in bucket_events if _safe_key(event.user)})
        hosts = sorted({_safe_key(event.host) for event in bucket_events if _safe_key(event.host)})
        src_ips = sorted({_safe_key(event.src_ip) for event in bucket_events if _safe_key(event.src_ip)})

        error_count = sum(1 for event in bucket_events if (event.severity or "").lower() == "error")
        warning_count = sum(1 for event in bucket_events if (event.severity or "").lower() in {"warn", "warning"})
        event_count = len(bucket_events)

        if error_count >= 5:
            severity = "high"
        elif error_count >= 1 or warning_count >= 3 or event_count >= 10:
            severity = "medium"
        else:
            severity = "low"

        if event_count >= 10 or error_count >= 3:
            confidence = "high"
        elif event_count >= 4 or error_count >= 1:
            confidence = "medium"
        else:
            confidence = "low"

        if severity == "high" and confidence == "high":
            priority = "critical"
        elif severity == "high" or confidence == "high":
            priority = "high"
        elif severity == "medium":
            priority = "medium"
        else:
            priority = "low"

        if error_count >= 3:
            attack_pattern = "error_spike"
        elif warning_count >= 3:
            attack_pattern = "warning_burst"
        elif any((event.event_action or "").lower() == "login_failed" for event in bucket_events):
            attack_pattern = "auth_fail_burst"
        else:
            attack_pattern = "unknown_anomalous_behavior"

        group_key = bucket_id.split("||", 1)[0]
        source_type = bucket_events[0].source_type if bucket_events else "generic_jsonl"

        summary_title = f"{severity.capitalize()} generic incident for {group_key}"
        summary_description = (
            f"Grouped {event_count} event(s) for {group_key} between "
            f"{first_seen or 'unknown'} and {last_seen or 'unknown'}, "
            f"with {error_count} error event(s), {warning_count} warning event(s), "
            f"across {len(users)} user(s), {len(hosts)} host(s), and {len(src_ips)} source IP(s). "
            f"Detected pattern: {attack_pattern}."
        )

        incidents.append(
            GenericIncident(
                incident_id=f"generic:{group_key}#{idx}",
                group_key=group_key,
                severity=severity,
                confidence=confidence,
                priority=priority,
                attack_pattern=attack_pattern,
                event_count=event_count,
                error_count=error_count,
                warning_count=warning_count,
                distinct_users=len(users),
                distinct_hosts=len(hosts),
                distinct_src_ips=len(src_ips),
                first_seen=first_seen,
                last_seen=last_seen,
                source_type=source_type,
                summary_title=summary_title,
                summary_description=summary_description,
            )
        )

    incidents.sort(
        key=lambda x: (
            {"critical": 4, "high": 3, "medium": 2, "low": 1}[x.priority],
            {"high": 3, "medium": 2, "low": 1}[x.severity],
            x.event_count,
            x.error_count,
        ),
        reverse=True,
    )
    return incidents