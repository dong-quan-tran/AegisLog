import json

from aegislog.mappings import load_mapping_file
from aegislog.normalized import NormalizedEvent

def _apply_field_mapping(record: dict, field_mapping: dict[str, str]) -> dict:
    mapped = {}

    for normalized_field, source_field in field_mapping.items():
        mapped[normalized_field] = record.get(source_field)

    return mapped


def parse_jsonl_with_mapping(
    path: str,
    mapping_path: str | None = None,
    *,
    default_source: str = "jsonl",
) -> list[NormalizedEvent]:
    field_mapping = load_mapping_file(mapping_path)
    events: list[NormalizedEvent] = []

    with open(path, "r", encoding="utf-8") as f:
        for line_number, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_number} of {path}: {exc}") from exc

            if not isinstance(record, dict):
                raise ValueError(
                    f"Each JSONL record must be an object; got {type(record).__name__} on line {line_number}."
                )

            mapped = _apply_field_mapping(record, field_mapping) if field_mapping else dict(record)

            if not mapped.get("source"):
                mapped["source"] = default_source

            event = NormalizedEvent.from_mapping(mapped)
            events.append(event)

    return events