from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from aegislog.normalized import NormalizedEvent
from aegislog.parsing.generic import load_generic_jsonl
from aegislog.adapters.ssh import load_ssh_normalized_events
from aegislog.adapters.apache import load_apache_normalized_events


class NormalizedLoadError(Exception):
    pass


def _ensure_file_exists(path: str) -> None:
    p = Path(path)
    if not p.exists():
        raise NormalizedLoadError(f"Input file not found: {path}")
    if not p.is_file():
        raise NormalizedLoadError(f"Input path is not a file: {path}")


def load_normalized_events(
    source_type: str,
    path: str,
    input_format: str = "jsonl",
    mapping: Optional[Dict[str, Any]] = None,
) -> Tuple[List[NormalizedEvent], list[str]]:
    """
    Load normalized events from a path for a given logical source_type.

    Returns (events, parse_errors).
    For SSH and Apache, parse_errors is always [] for now.
    """
    _ensure_file_exists(path)

    source_type = source_type.lower()

    if source_type == "generic":
        if input_format != "jsonl":
            raise NormalizedLoadError(
                f"Unsupported input_format {input_format!r} for source_type='generic'. "
                "Expected: jsonl."
            )
        events, errors = load_generic_jsonl(path, mapping=mapping)
        return events, errors

    if source_type == "ssh":
        events = load_ssh_normalized_events(path)
        return events, []

    if source_type == "apache":
        events = load_apache_normalized_events(path)
        return events, []

    raise NormalizedLoadError(
        f"Unsupported source_type {source_type!r}. "
        "Expected one of: generic, ssh, apache."
    )