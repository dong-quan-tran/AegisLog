from __future__ import annotations

from typing import Iterable, List, Tuple

from aegislog.normalized import NormalizedEvent
from aegislog.parsing.generic import load_generic_jsonl
from aegislog.adapters.ssh import load_ssh_normalized_events
from aegislog.adapters.apache import load_apache_normalized_events


class NormalizedLoadError(Exception):
    pass


def load_normalized_events(
    source_type: str,
    path: str,
    input_format: str = "jsonl",
) -> Tuple[List[NormalizedEvent], list[str]]:
    """
    Load normalized events from a path for a given logical source_type.

    Returns (events, parse_errors).
    For SSH and Apache, parse_errors is always [] for now.
    """
    source_type = source_type.lower()

    if source_type == "generic":
        events, errors = load_generic_jsonl(path)
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