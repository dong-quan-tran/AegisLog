from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, List, Optional

from aegislog.normalized import NormalizedEvent
from aegislog.parsing.apache_error import parse_error_file


def _coerce_timestamp(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    text = str(value).strip()
    return text or None


def _coerce_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _get_attr(obj: Any, *names: str) -> Any:
    for name in names:
        if isinstance(obj, dict) and name in obj:
            return obj[name]
        if hasattr(obj, name):
            return getattr(obj, name)
    return None


def _normalize_apache_level(level: Optional[str]) -> Optional[str]:
    if level is None:
        return None
    return str(level).strip().lower() or None


def _map_severity(level: Optional[str]) -> str:
    level = _normalize_apache_level(level)

    if level in {"emerg", "alert", "crit", "critical", "error"}:
        return "error"
    if level in {"warn", "warning"}:
        return "warn"
    if level in {"notice", "info", "debug", "trace", "trace1", "trace2", "trace3", "trace4", "trace5", "trace6", "trace7", "trace8"}:
        return "info"
    return "info"


def _map_event_action(level: Optional[str], raw_message: str) -> str:
    level = _normalize_apache_level(level)
    text = (raw_message or "").lower()

    if "segmentation fault" in text:
        return "process_crash"
    if "client denied" in text:
        return "access_denied"
    if "file does not exist" in text:
        return "missing_file"
    if "permission denied" in text:
        return "permission_denied"
    if "caught sigterm" in text or "shutting down" in text:
        return "service_shutdown"
    if "resuming normal operations" in text or "configured -- resuming normal operations" in text:
        return "service_start"
    if level in {"emerg", "alert", "crit", "critical", "error"}:
        return "apache_error"
    if level in {"warn", "warning"}:
        return "apache_warn"
    if level in {"notice", "info", "debug"}:
        return "apache_notice"
    return "apache_event"


def apache_record_to_normalized_event(record: Any) -> NormalizedEvent:
    raw_message = _coerce_text(_get_attr(record, "raw", "message", "raw_message")) or ""
    timestamp = _coerce_timestamp(_get_attr(record, "timestamp", "ts", "time"))
    level = _coerce_text(_get_attr(record, "user_agent", "level"))
    source = _coerce_text(_get_attr(record, "source")) or "apache_error"

    severity = _map_severity(level)
    event_action = _map_event_action(level, raw_message)

    extra = {}
    if level is not None:
        extra["apache_level"] = level
    if source is not None:
        extra["parser_source"] = source

    return NormalizedEvent(
        timestamp=timestamp,
        source_type="apache",
        raw_message=raw_message,
        event_category="application",
        event_action=event_action,
        severity=severity,
        src_ip=None,
        dst_ip=None,
        user=None,
        host=None,
        service="apache",
        status_code=None,
        message=raw_message,
        session_hint=None,
        extra=extra,
    )


def load_apache_normalized_events(path: str) -> List[NormalizedEvent]:
    records = parse_error_file(path)
    return [apache_record_to_normalized_event(record) for record in records]


def summarize_apache_normalized_events(events: Iterable[NormalizedEvent]) -> dict:
    total_events = 0
    severity_counts = {}
    event_action_counts = {}
    apache_level_counts = {}

    for event in events:
        total_events += 1

        severity = event.severity or "unknown"
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

        action = event.event_action or "unknown"
        event_action_counts[action] = event_action_counts.get(action, 0) + 1

        level = event.extra.get("apache_level") if event.extra else None
        level = level or "unknown"
        apache_level_counts[level] = apache_level_counts.get(level, 0) + 1

    return {
        "total_events": total_events,
        "severity_counts": severity_counts,
        "event_action_counts": event_action_counts,
        "apache_level_counts": apache_level_counts,
        "source_type": "apache",
    }