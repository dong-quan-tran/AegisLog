from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from aegislog.incident.evidence import IncidentEvidence
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


@dataclass
class GenericIncidentBundle:
    incident: GenericIncident
    events: List[NormalizedEvent]

    def to_dict(self) -> Dict[str, Any]:
        data = self.incident.to_dict()
        data["events"] = [event.to_dict() for event in self.events]
        return data


def _window_bucket(ts: Optional[datetime], minutes: int) -> str:
    if ts is None:
        return "no_time"
    floored_minute = (ts.minute // minutes) * minutes
    bucket = ts.replace(minute=floored_minute, second=0, microsecond=0)
    return bucket.isoformat()


def group_generic_events_to_incident_bundles(
    events: List[NormalizedEvent],
    *,
    window_minutes: int = 15,
) -> List[GenericIncidentBundle]:
    buckets: Dict[str, List[NormalizedEvent]] = defaultdict(list)

    for event in events:
        ts = _parse_dt(event.timestamp)
        group_key = _guess_group_key(event)
        bucket_key = _window_bucket(ts, window_minutes)
        buckets[f"{group_key}||{bucket_key}"].append(event)

    bundles: List[GenericIncidentBundle] = []

    for idx, (bucket_id, bucket_events) in enumerate(sorted(buckets.items()), start=1):
        timestamps = [_parse_dt(event.timestamp) for event in bucket_events]
        timestamps = [ts for ts in timestamps if ts is not None]

        first_seen = min(timestamps).isoformat() if timestamps else None
        last_seen = max(timestamps).isoformat() if timestamps else None

        users = sorted({_safe_key(event.user) for event in bucket_events if _safe_key(event.user)})
        hosts = sorted({_safe_key(event.host) for event in bucket_events if _safe_key(event.host)})
        src_ips = sorted({_safe_key(event.src_ip) for event in bucket_events if _safe_key(event.src_ip)})

        error_count = sum(1 for event in bucket_events if (event.severity or "").lower() == "error")
        warning_count = sum(
            1 for event in bucket_events if (event.severity or "").lower() in {"warn", "warning"}
        )
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

        incident = GenericIncident(
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
        bundles.append(GenericIncidentBundle(incident=incident, events=bucket_events))

    bundles.sort(
        key=lambda x: (
            {"critical": 4, "high": 3, "medium": 2, "low": 1}[x.incident.priority],
            {"high": 3, "medium": 2, "low": 1}[x.incident.severity],
            x.incident.event_count,
            x.incident.error_count,
        ),
        reverse=True,
    )
    return bundles


def group_generic_events_to_incidents(
    events: List[NormalizedEvent],
    *,
    window_minutes: int = 15,
) -> List[GenericIncident]:
    return [
        bundle.incident
        for bundle in group_generic_events_to_incident_bundles(
            events,
            window_minutes=window_minutes,
        )
    ]


def build_generic_incident_evidence(
    incident: GenericIncident,
    events: List[NormalizedEvent],
    *,
    input_format: str = "jsonl",
    window_minutes: int = 15,
) -> IncidentEvidence:
    highlights: List[str] = []

    if incident.group_key:
        highlights.append(f"Grouped by key: {incident.group_key}.")
    highlights.append(
        f"Observed {incident.event_count} event(s), including {incident.error_count} error(s) "
        f"and {incident.warning_count} warning(s)."
    )
    highlights.append(
        f"Distinct entities: {incident.distinct_users} user(s), {incident.distinct_hosts} host(s), "
        f"{incident.distinct_src_ips} source IP(s)."
    )
    if incident.first_seen or incident.last_seen:
        highlights.append(
            f"Time range: {incident.first_seen or 'unknown'} to {incident.last_seen or 'unknown'}."
        )
    highlights.append(
        f"Source type '{incident.source_type}' grouped into pattern '{incident.attack_pattern}'."
    )

    sample_events = []
    session_rows = []

    for idx, event in enumerate(events[:5], start=1):
        sample_event = {
            "timestamp": event.timestamp,
            "event_category": event.event_category,
            "event_action": event.event_action,
            "severity": event.severity,
            "src_ip": event.src_ip,
            "dst_ip": event.dst_ip,
            "user": event.user,
            "host": event.host,
            "service": event.service,
            "message": event.message,
            "session_hint": event.session_hint,
        }
        sample_events.append(sample_event)

        session_rows.append(
            {
                "session_id": event.session_hint or f"{incident.incident_id}:event-{idx}",
                "anomaly_score": 0.0,
                "start_time": event.timestamp,
                "end_time": event.timestamp,
                "ip": event.src_ip,
                "user": event.user,
                "auth_failed": 1 if (event.event_action or "").lower() == "login_failed" else 0,
                "auth_success": 1 if (event.event_action or "").lower() == "login_success" else 0,
                "event_count": 1,
                "event_type": event.event_action or event.event_category or "generic_event",
                "notes": [
                    f"severity={event.severity or 'unknown'}",
                    f"service={event.service or 'unknown'}",
                    f"host={event.host or 'unknown'}",
                ],
            }
        )

    representative_ip = next((event.src_ip for event in events if event.src_ip), None)
    representative_user = next((event.user for event in events if event.user), None)

    return IncidentEvidence(
        incident_id=incident.incident_id,
        log_type=incident.source_type,
        ip=representative_ip,
        user=representative_user,
        model_type="generic",
        feature_version="generic-v1",
        threshold_percentile=0.0,
        severity=incident.severity,
        confidence=incident.confidence,
        priority=incident.priority,
        attack_pattern=incident.attack_pattern,
        highlights=highlights,
        sessions=session_rows,
        extra={
            "input_format": input_format,
            "window_minutes": window_minutes,
            "group_key": incident.group_key,
            "source_type": incident.source_type,
            "total_events": incident.event_count,
            "error_count": incident.error_count,
            "warning_count": incident.warning_count,
            "distinct_users": incident.distinct_users,
            "distinct_hosts": incident.distinct_hosts,
            "distinct_src_ips": incident.distinct_src_ips,
            "first_seen": incident.first_seen,
            "last_seen": incident.last_seen,
            "summary_title": incident.summary_title,
            "summary_description": incident.summary_description,
            "sample_events": sample_events,
        },
    )