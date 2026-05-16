from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from aegislog.normalized import NormalizedEvent
from aegislog.adapters.ssh import load_ssh_normalized_events
from aegislog.adapters.apache import load_apache_normalized_events
from aegislog.mappings import load_mapping_file
from aegislog.parsing.generic import load_generic_jsonl, load_generic_syslog


class NormalizedLoadError(Exception):
    pass


def _ensure_file_exists(path: str) -> None:
    p = Path(path)
    if not p.exists():
        raise NormalizedLoadError(f"Input file not found: {path}")
    if not p.is_file():
        raise NormalizedLoadError(f"Input path is not a file: {path}")


def _resolve_mapping(
    mapping: Optional[Dict[str, Any]] = None,
    mapping_path: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    if mapping is not None and mapping_path is not None:
        raise NormalizedLoadError("Pass either mapping or mapping_path, not both.")

    if mapping_path is not None:
        try:
            return load_mapping_file(mapping_path)
        except (OSError, ValueError, RuntimeError) as exc:
            raise NormalizedLoadError(f"Failed to load mapping file: {exc}") from exc

    return mapping


def load_normalized_events(
    source_type: str,
    path: str,
    input_format: str = "jsonl",
    mapping: Optional[Dict[str, Any]] = None,
    mapping_path: Optional[str] = None,
) -> Tuple[List[NormalizedEvent], list[str]]:
    """
    Load normalized events from a path for a given logical source_type.

    Returns (events, parse_errors).
    For SSH and Apache, parse_errors is always [] for now.
    """
    _ensure_file_exists(path)

    source_type = source_type.lower()
    input_format = input_format.lower()
    resolved_mapping = _resolve_mapping(mapping=mapping, mapping_path=mapping_path)

    if source_type == "generic":
        try:
            if input_format == "jsonl":
                events, errors = load_generic_jsonl(path, mapping=resolved_mapping)
                return events, errors

            if input_format == "syslog":
                events, errors = load_generic_syslog(path, mapping=resolved_mapping)
                return events, errors

            raise NormalizedLoadError(
                f"Unsupported input_format {input_format!r} for source_type='generic'. "
                "Expected one of: jsonl, syslog."
            )
        except (ValueError, OSError) as exc:
            raise NormalizedLoadError(
                f"Failed to load generic {input_format}: {exc}"
            ) from exc

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