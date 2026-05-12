from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Tuple

from aegislog.normalized import NormalizedEvent


def load_generic_jsonl(path: str) -> Tuple[List[NormalizedEvent], List[str]]:
    events: List[NormalizedEvent] = []
    errors: List[str] = []

    with open(path, "r", encoding="utf-8") as f:
        for line_no, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line:
                continue

            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append(f"line {line_no}: invalid JSON ({exc.msg})")
                continue

            if not isinstance(payload, dict):
                errors.append(f"line {line_no}: JSON value must be an object")
                continue

            try:
                event = NormalizedEvent.from_mapping(payload, source_type="generic_jsonl")
            except Exception as exc:
                errors.append(f"line {line_no}: normalization failed ({exc})")
                continue

            events.append(event)

    return events, errors


def summarize_normalized_events(events: Iterable[NormalizedEvent]) -> Dict[str, Any]:
    total = 0
    severities: Dict[str, int] = {}
    categories: Dict[str, int] = {}
    actions: Dict[str, int] = {}

    for event in events:
        total += 1

        if event.severity:
            severities[event.severity] = severities.get(event.severity, 0) + 1

        if event.event_category:
            categories[event.event_category] = categories.get(event.event_category, 0) + 1

        if event.event_action:
            actions[event.event_action] = actions.get(event.event_action, 0) + 1

    return {
        "total_events": total,
        "severity_counts": dict(sorted(severities.items())),
        "event_category_counts": dict(sorted(categories.items())),
        "event_action_counts": dict(sorted(actions.items())),
    }