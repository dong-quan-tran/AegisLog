from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from aegislog.normalized import NormalizedEvent


_SYSLOG_RE = re.compile(
    r"""
    ^
    (?:<(?P<pri>\d{1,3})>)?
    (?P<timestamp>[A-Z][a-z]{2}\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2})
    \s+
    (?P<hostname>\S+)
    \s+
    (?P<message>.*?)
    \s*$
    """,
    re.VERBOSE,
)

_SYSLOG_TAG_RE = re.compile(
    r"""
    ^
    (?P<tag>[A-Za-z0-9_.\-/]+)
    (?:\[(?P<pid>\d+)\])?
    (?:
        :\s*
        |
        \s+
    )?
    (?P<content>.*)
    $
    """,
    re.VERBOSE,
)

_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

_SYSLOG_SEVERITY = {
    0: "emergency",
    1: "alert",
    2: "critical",
    3: "error",
    4: "warn",
    5: "notice",
    6: "info",
    7: "debug",
}


def _coerce_mapping_field_names(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    if isinstance(value, (list, tuple)):
        result: List[str] = []
        for item in value:
            if item is None:
                continue
            text = str(item).strip()
            if text:
                result.append(text)
        return result
    return []


def _extract_mapped_record(
    record: Dict[str, Any],
    mapping: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Build a record shaped for NormalizedEvent.from_mapping(...) using a
    simple alias-mapping config.

    Mapping shape:
    {
      "source_type": "generic_jsonl",
      "fields": {
        "timestamp": ["@timestamp", "time", "ts"],
        "message": ["msg", "message"]
      },
      "defaults": {
        "event_category": "auth"
      }
    }
    """
    if not mapping:
        return dict(record)

    fields = mapping.get("fields")
    if not isinstance(fields, dict):
        return dict(record)

    mapped: Dict[str, Any] = dict(record)

    defaults = mapping.get("defaults", {})
    if isinstance(defaults, dict):
        for key, value in defaults.items():
            mapped.setdefault(key, value)

    for normalized_field, candidate_names in fields.items():
        aliases = _coerce_mapping_field_names(candidate_names)
        for alias in aliases:
            if alias in record and record[alias] is not None:
                mapped[normalized_field] = record[alias]
                break

    source_type = mapping.get("source_type")
    if isinstance(source_type, str) and source_type.strip():
        mapped["_mapped_source_type"] = source_type.strip()

    return mapped


def _parse_syslog_timestamp(value: str) -> str:
    """
    RFC 3164 timestamps do not include a year or timezone.
    Assume current year and UTC for normalization.
    """
    text = value.strip()
    parts = text.split()
    if len(parts) != 3:
        return text

    month_text, day_text, time_text = parts
    month = _MONTHS.get(month_text)
    if month is None:
        return text

    try:
        day = int(day_text)
        hh, mm, ss = [int(x) for x in time_text.split(":", 2)]
        now = datetime.now(timezone.utc)
        dt = datetime(now.year, month, day, hh, mm, ss, tzinfo=timezone.utc)
        return dt.isoformat()
    except (TypeError, ValueError):
        return text


def _extract_syslog_tag_parts(message: str) -> Dict[str, Any]:
    msg = message.strip()
    match = _SYSLOG_TAG_RE.match(msg)
    if not match:
        return {"message": msg}

    tag = match.group("tag")
    pid = match.group("pid")
    content = (match.group("content") or "").strip()

    result: Dict[str, Any] = {
        "message": content or msg,
        "service": tag,
    }

    if pid is not None:
        result["pid"] = pid

    return result


def _parse_syslog_line(line: str) -> Dict[str, Any]:
    match = _SYSLOG_RE.match(line)
    if not match:
        raise ValueError("line does not match RFC3164-style syslog format")

    pri_raw = match.group("pri")
    timestamp_raw = match.group("timestamp")
    hostname = match.group("hostname")
    message = match.group("message").strip()

    pri: Optional[int] = None
    severity: Optional[str] = None
    facility: Optional[int] = None

    if pri_raw is not None:
        pri = int(pri_raw)
        facility = pri // 8
        severity_code = pri % 8
        severity = _SYSLOG_SEVERITY.get(severity_code, "unknown")

    tag_parts = _extract_syslog_tag_parts(message)

    record: Dict[str, Any] = {
        "timestamp": _parse_syslog_timestamp(timestamp_raw),
        "host": hostname,
        "raw_message": line,
        "severity": severity,
        "event_category": "syslog",
        **tag_parts,
    }

    if pri is not None:
        record["pri"] = pri
    if facility is not None:
        record["facility"] = facility

    return record


def load_generic_jsonl(
    path: str,
    mapping: Optional[Dict[str, Any]] = None,
) -> Tuple[List[NormalizedEvent], List[str]]:
    """
    Load JSON Lines records and normalize them into NormalizedEvent objects.

    Returns (events, errors).
    """
    events: List[NormalizedEvent] = []
    errors: List[str] = []

    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        for line_no, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError as e:
                errors.append(f"line {line_no}: invalid JSON ({e})")
                continue

            if not isinstance(data, dict):
                errors.append(
                    f"line {line_no}: expected JSON object, got {type(data).__name__}"
                )
                continue

            try:
                mapped = _extract_mapped_record(data, mapping)
                source_type = mapped.pop("_mapped_source_type", None) or "generic_jsonl"
                event = NormalizedEvent.from_mapping(
                    mapped,
                    source_type=source_type,
                )
                events.append(event)
            except Exception as e:
                errors.append(f"line {line_no}: failed to normalize record ({e})")

    return events, errors


def load_generic_syslog(
    path: str,
    mapping: Optional[Dict[str, Any]] = None,
) -> Tuple[List[NormalizedEvent], List[str]]:
    """
    Load RFC3164-style syslog lines and normalize them into NormalizedEvent objects.

    Returns (events, errors).
    """
    events: List[NormalizedEvent] = []
    errors: List[str] = []

    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        for line_no, raw_line in enumerate(f, start=1):
            line = raw_line.rstrip("\n")
            if not line.strip():
                continue

            try:
                data = _parse_syslog_line(line)
                mapped = _extract_mapped_record(data, mapping)
                source_type = mapped.pop("_mapped_source_type", None) or "generic_syslog"
                event = NormalizedEvent.from_mapping(
                    mapped,
                    source_type=source_type,
                )
                events.append(event)
            except Exception as e:
                errors.append(f"line {line_no}: failed to parse syslog line ({e})")

    return events, errors


def summarize_normalized_events(events: Iterable[NormalizedEvent]) -> dict:
    total_events = 0
    severity_counts: Dict[str, int] = {}
    event_category_counts: Dict[str, int] = {}
    event_action_counts: Dict[str, int] = {}

    for event in events:
        total_events += 1

        severity = event.severity or "unknown"
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

        category = event.event_category or "unknown"
        event_category_counts[category] = event_category_counts.get(category, 0) + 1

        action = event.event_action or "unknown"
        event_action_counts[action] = event_action_counts.get(action, 0) + 1

    return {
        "total_events": total_events,
        "severity_counts": severity_counts,
        "event_category_counts": event_category_counts,
        "event_action_counts": event_action_counts,
    }