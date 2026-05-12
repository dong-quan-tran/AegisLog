from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, List, Optional

from aegislog.normalized import NormalizedEvent
from aegislog.parsing.auth_ssh import parse_ssh_file


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


def _infer_event_action(record: Any, raw_message: str) -> str:
    status = _get_attr(record, "status")
    text = (raw_message or "").lower()

    if status == 401 or "failed password" in text:
        return "login_failed"
    if status == 200 or "accepted password" in text:
        return "login_success"
    if "accepted publickey" in text:
        return "login_success"
    if "invalid user" in text:
        return "invalid_user"
    if "maximum authentication attempts exceeded" in text:
        return "auth_attempts_exceeded"
    if "connection closed" in text:
        return "connection_closed"
    if "disconnect" in text:
        return "disconnect"
    return "ssh_event"


def _infer_severity(action: str) -> str:
    if action in {"login_failed", "invalid_user", "auth_attempts_exceeded"}:
        return "warn"
    if action in {"connection_closed", "disconnect", "login_success"}:
        return "info"
    return "info"


def ssh_record_to_normalized_event(record: Any) -> NormalizedEvent:
    raw_message = _coerce_text(
        _get_attr(record, "raw", "message", "raw_message", "msg", "line")
    ) or ""

    timestamp = _coerce_timestamp(_get_attr(record, "timestamp", "ts", "time"))
    src_ip = _coerce_text(_get_attr(record, "ip", "src_ip", "client_ip", "source_ip"))
    user = _coerce_text(_get_attr(record, "user", "username"))
    status_code = _get_attr(record, "status")
    source = _coerce_text(_get_attr(record, "source")) or "ssh_auth"

    event_action = _infer_event_action(record, raw_message)
    severity = _infer_severity(event_action)

    session_hint = None
    if src_ip and user:
        session_hint = f"{src_ip}|{user}"
    elif src_ip:
        session_hint = src_ip
    elif user:
        session_hint = user

    extra = {}
    method = _coerce_text(_get_attr(record, "method"))
    path = _coerce_text(_get_attr(record, "path"))
    user_agent = _coerce_text(_get_attr(record, "user_agent"))

    if method is not None:
        extra["method"] = method
    if path is not None:
        extra["path"] = path
    if user_agent is not None:
        extra["user_agent"] = user_agent

    return NormalizedEvent(
        timestamp=timestamp,
        source_type="ssh",
        raw_message=raw_message,
        event_category="auth",
        event_action=event_action,
        severity=severity,
        src_ip=src_ip,
        dst_ip=None,
        user=user,
        host=None,
        service="ssh",
        status_code=status_code,
        message=raw_message,
        session_hint=session_hint,
        extra=extra,
    )


def load_ssh_normalized_events(path: str) -> List[NormalizedEvent]:
    records = parse_ssh_file(path)
    return [ssh_record_to_normalized_event(record) for record in records]


def summarize_ssh_normalized_events(events: Iterable[NormalizedEvent]) -> dict:
    total_events = 0
    severity_counts = {}
    event_action_counts = {}
    distinct_users = set()
    distinct_src_ips = set()

    for event in events:
        total_events += 1

        severity = event.severity or "unknown"
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

        action = event.event_action or "unknown"
        event_action_counts[action] = event_action_counts.get(action, 0) + 1

        if event.user:
            distinct_users.add(event.user)
        if event.src_ip:
            distinct_src_ips.add(event.src_ip)

    return {
        "total_events": total_events,
        "severity_counts": severity_counts,
        "event_action_counts": event_action_counts,
        "distinct_users": len(distinct_users),
        "distinct_src_ips": len(distinct_src_ips),
        "source_type": "ssh",
    }