from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from aegislog.normalized import NormalizedEvent


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
        "message": ["msg", "message"],
        ...
      }
    }
    """
    if not mapping:
        return dict(record)

    fields = mapping.get("fields")
    if not isinstance(fields, dict):
        return dict(record)

    mapped: Dict[str, Any] = dict(record)

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