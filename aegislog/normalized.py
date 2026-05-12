from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional


def _coerce_iso_timestamp(value: Any) -> Optional[str]:
    if value is None:
        return None

    if isinstance(value, datetime):
        return value.isoformat()

    text = str(value).strip()
    if not text:
        return None

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        return datetime.fromisoformat(text).isoformat()
    except ValueError:
        return text


def _coerce_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


@dataclass
class NormalizedEvent:
    timestamp: Optional[str]
    source_type: str
    raw_message: Optional[str] = None
    event_category: Optional[str] = None
    event_action: Optional[str] = None
    severity: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    user: Optional[str] = None
    host: Optional[str] = None
    service: Optional[str] = None
    status_code: Optional[int] = None
    message: Optional[str] = None
    session_hint: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "source_type": self.source_type,
            "raw_message": self.raw_message,
            "event_category": self.event_category,
            "event_action": self.event_action,
            "severity": self.severity,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "user": self.user,
            "host": self.host,
            "service": self.service,
            "status_code": self.status_code,
            "message": self.message,
            "session_hint": self.session_hint,
            "extra": self.extra,
        }

    @classmethod
    def from_mapping(
        cls,
        data: Dict[str, Any],
        *,
        source_type: str = "generic_jsonl",
    ) -> "NormalizedEvent":
        extra = dict(data)

        timestamp = (
            extra.pop("timestamp", None)
            or extra.pop("@timestamp", None)
            or extra.pop("time", None)
            or extra.pop("ts", None)
        )
        raw_message = extra.get("raw_message")
        message = (
            extra.pop("message", None)
            or extra.pop("msg", None)
            or extra.pop("event_message", None)
        )

        severity = (
            extra.pop("severity", None)
            or extra.pop("level", None)
            or extra.pop("log_level", None)
        )

        src_ip = (
            extra.pop("src_ip", None)
            or extra.pop("source_ip", None)
            or extra.pop("client_ip", None)
            or extra.pop("ip", None)
        )

        dst_ip = (
            extra.pop("dst_ip", None)
            or extra.pop("destination_ip", None)
            or extra.pop("server_ip", None)
        )

        user = (
            extra.pop("user", None)
            or extra.pop("username", None)
            or extra.pop("account", None)
        )

        host = (
            extra.pop("host", None)
            or extra.pop("hostname", None)
            or extra.pop("server", None)
        )

        service = (
            extra.pop("service", None)
            or extra.pop("app", None)
            or extra.pop("application", None)
        )

        event_category = (
            extra.pop("event_category", None)
            or extra.pop("category", None)
            or extra.pop("event_type", None)
        )

        event_action = (
            extra.pop("event_action", None)
            or extra.pop("action", None)
            or extra.pop("operation", None)
        )

        session_hint = (
            extra.pop("session_hint", None)
            or extra.pop("session_id", None)
            or extra.pop("trace_id", None)
            or extra.pop("request_id", None)
        )

        status_code = extra.pop("status_code", None)
        if status_code is not None:
            try:
                status_code = int(status_code)
            except (TypeError, ValueError):
                pass

        if raw_message is None and message is not None:
            raw_message = str(message)

        return cls(
            timestamp=_coerce_iso_timestamp(timestamp),
            source_type=source_type,
            raw_message=_coerce_str(raw_message),
            event_category=_coerce_str(event_category),
            event_action=_coerce_str(event_action),
            severity=_coerce_str(severity),
            src_ip=_coerce_str(src_ip),
            dst_ip=_coerce_str(dst_ip),
            user=_coerce_str(user),
            host=_coerce_str(host),
            service=_coerce_str(service),
            status_code=status_code,
            message=_coerce_str(message),
            session_hint=_coerce_str(session_hint),
            extra=extra,
        )