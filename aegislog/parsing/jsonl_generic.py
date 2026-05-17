from __future__ import annotations

import json
from typing import List

from aegislog.mappings import flatten_mapping_fields, load_mapping_file
from aegislog.normalized import NormalizedEvent


def _apply_field_mapping(record: dict, field_mapping: dict[str, str]) -> dict:
    mapped = {}

    for normalized_field, source_field in field_mapping.items():
        mapped[normalized_field] = record.get(source_field)

    for key, value in record.items():
        mapped.setdefault(key, value)

    return mapped


def parse_jsonl_with_mapping(path: str, mapping_path: str | None) -> List[NormalizedEvent]:
    field_mapping = {}
    if mapping_path is not None:
        mapping = load_mapping_file(mapping_path)
        field_mapping = flatten_mapping_fields(mapping)

    events: List[NormalizedEvent] = []

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            record = json.loads(line)
            if not isinstance(record, dict):
                continue

            mapped = _apply_field_mapping(record, field_mapping) if field_mapping else dict(record)
            events.append(NormalizedEvent.from_mapping(mapped, source_type="generic_jsonl"))

    return events