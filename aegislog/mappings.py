from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import yaml


def _normalize_field_aliases(fields: Any) -> Dict[str, list[str]]:
    if not isinstance(fields, dict):
        raise ValueError("mapping 'fields' must be an object")

    normalized: Dict[str, list[str]] = {}

    for normalized_field, source_names in fields.items():
        if isinstance(source_names, str):
            names = [source_names]
        elif isinstance(source_names, list):
            names = [str(item).strip() for item in source_names if str(item).strip()]
        else:
            raise ValueError(
                f"mapping field '{normalized_field}' must be a string or list of strings"
            )

        if not names:
            raise ValueError(f"mapping field '{normalized_field}' must not be empty")

        normalized[str(normalized_field)] = names

    return normalized


def normalize_mapping(mapping: Dict[str, Any] | None) -> Dict[str, Any] | None:
    if mapping is None:
        return None

    if not isinstance(mapping, dict):
        raise ValueError("mapping must be an object")

    if "fields" in mapping:
        normalized: Dict[str, Any] = {
            "fields": _normalize_field_aliases(mapping.get("fields", {}))
        }

        if "defaults" in mapping:
            defaults = mapping["defaults"]
            if not isinstance(defaults, dict):
                raise ValueError("mapping 'defaults' must be an object")
            normalized["defaults"] = dict(defaults)

        if "source_type" in mapping and mapping["source_type"] is not None:
            normalized["source_type"] = str(mapping["source_type"]).strip()

        return normalized

    return {"fields": _normalize_field_aliases(mapping)}


def flatten_mapping_fields(mapping: Dict[str, Any] | None) -> Dict[str, str]:
    """
    Compatibility helper for older code/tests that expect a flat
    normalized_field -> source_field mapping.
    """
    normalized = normalize_mapping(mapping)
    if not normalized:
        return {}

    flat: Dict[str, str] = {}
    for normalized_field, aliases in normalized["fields"].items():
        if aliases:
            flat[normalized_field] = aliases[0]
    return flat


def load_mapping_file(path: str) -> Dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Mapping file not found: {path}")

    text = p.read_text(encoding="utf-8")

    if p.suffix.lower() == ".json":
        raw = json.loads(text)
    elif p.suffix.lower() in {".yaml", ".yml"}:
        raw = yaml.safe_load(text)
    else:
        raise ValueError("Mapping file must be .json, .yaml, or .yml")

    return normalize_mapping(raw) or {"fields": {}}


def load_mapping_file_flat(path: str) -> Dict[str, str]:
    """
    Backward-compatible loader for older parser/tests.
    """
    return flatten_mapping_fields(load_mapping_file(path))