from __future__ import annotations

import os
import tempfile
from typing import Any, Callable, Dict, TypeVar

from aegislog.ai.client import LLMError, generate_incident_analysis
from aegislog.ai.prompts_structured import build_structured_incident_analysis_prompt
from aegislog.adapters.apache import summarize_apache_normalized_events
from aegislog.adapters.ssh import summarize_ssh_normalized_events
from aegislog.incidents_generic import (
    build_generic_incident_evidence,
    group_generic_events_to_incident_bundles,
    group_generic_events_to_incidents,
)
from aegislog.incidents_normalized import build_normalized_incident_evidence
from aegislog.normalized_loader import load_normalized_events
from aegislog.parsing.generic import summarize_normalized_events

T = TypeVar("T")


def _write_temp_content(content: str) -> str:
    fd, path = tempfile.mkstemp(prefix="aegislog-api-", suffix=".log", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    return path


def _with_temp_content(content: str, fn: Callable[[str], T]) -> T:
    path = _write_temp_content(content)
    try:
        return fn(path)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _summarize_events(source_type: str, events: list) -> Dict[str, Any]:
    if source_type == "ssh":
        return summarize_ssh_normalized_events(events)
    if source_type == "apache":
        return summarize_apache_normalized_events(events)
    return summarize_normalized_events(events)


def _maybe_ai_analysis(evidence: Any, use_ai: bool) -> Dict[str, Any]:
    if not use_ai:
        return {}

    try:
        prompt = build_structured_incident_analysis_prompt(evidence)
        return {"ai_analysis": generate_incident_analysis(prompt)}
    except LLMError as exc:
        return {"ai_error": str(exc)}


def normalize_logs(
    *,
    content: str,
    source_type: str,
    input_format: str,
    mapping: Dict[str, Any] | None,
    top: int,
) -> Dict[str, Any]:
    def _run(path: str) -> Dict[str, Any]:
        events, errors = load_normalized_events(
            source_type=source_type,
            path=path,
            input_format=input_format,
            mapping=mapping if source_type == "generic" else None,
        )

        preview = [event.to_dict() for event in events[:top]]
        summary = _summarize_events(source_type, events)

        return {
            "source_type": source_type,
            "input_format": input_format,
            "mapping": mapping if source_type == "generic" else None,
            "summary": summary,
            "preview": preview,
            "parse_errors": errors,
        }

    return _with_temp_content(content, _run)


def generic_incidents(
    *,
    content: str,
    input_format: str,
    mapping: Dict[str, Any] | None,
    window_minutes: int,
    top: int,
) -> Dict[str, Any]:
    def _run(path: str) -> Dict[str, Any]:
        events, errors = load_normalized_events(
            source_type="generic",
            path=path,
            input_format=input_format,
            mapping=mapping,
        )

        incidents = group_generic_events_to_incidents(
            events,
            window_minutes=window_minutes,
        )

        return {
            "source_type": "generic",
            "input_format": input_format,
            "mapping": mapping,
            "window_minutes": window_minutes,
            "total_events": len(events),
            "total_incidents": len(incidents),
            "incidents": [incident.to_dict() for incident in incidents[:top]],
            "parse_errors": errors,
        }

    return _with_temp_content(content, _run)


def normalized_incidents(
    *,
    content: str,
    source_type: str,
    input_format: str,
    mapping: Dict[str, Any] | None,
    window_minutes: int,
    top: int,
) -> Dict[str, Any]:
    def _run(path: str) -> Dict[str, Any]:
        events, errors = load_normalized_events(
            source_type=source_type,
            path=path,
            input_format=input_format,
            mapping=mapping if source_type == "generic" else None,
        )

        incidents = group_generic_events_to_incidents(
            events,
            window_minutes=window_minutes,
        )

        return {
            "source_type": source_type,
            "input_format": input_format,
            "mapping": mapping if source_type == "generic" else None,
            "window_minutes": window_minutes,
            "total_events": len(events),
            "total_incidents": len(incidents),
            "incidents": [incident.to_dict() for incident in incidents[:top]],
            "parse_errors": errors,
        }

    return _with_temp_content(content, _run)


def generic_explain(
    *,
    content: str,
    input_format: str,
    mapping: Dict[str, Any] | None,
    window_minutes: int,
    index: int,
    first: bool,
    use_ai: bool,
) -> Dict[str, Any]:
    def _run(path: str) -> Dict[str, Any]:
        events, errors = load_normalized_events(
            source_type="generic",
            path=path,
            input_format=input_format,
            mapping=mapping,
        )

        bundles = group_generic_events_to_incident_bundles(
            events,
            window_minutes=window_minutes,
        )

        if not bundles:
            return {
                "source_type": "generic",
                "input_format": input_format,
                "mapping": mapping,
                "window_minutes": window_minutes,
                "total_events": len(events),
                "total_incidents": 0,
                "parse_errors": errors,
                "message": "No generic incidents found.",
            }

        selected_index = 0 if first else index
        if selected_index < 0 or selected_index >= len(bundles):
            raise ValueError(
                f"Invalid index {selected_index}. There are {len(bundles)} generic incident(s)."
            )

        bundle = bundles[selected_index]
        incident = bundle.incident
        evidence = build_generic_incident_evidence(
            incident,
            bundle.events,
            input_format=input_format,
            window_minutes=window_minutes,
        )

        payload = {
            "source_type": "generic",
            "input_format": input_format,
            "mapping": mapping,
            "window_minutes": window_minutes,
            "selected_index": selected_index,
            "incident": incident.to_dict(),
            "incident_evidence": evidence.to_dict(),
            "parse_errors": errors,
        }
        payload.update(_maybe_ai_analysis(evidence, use_ai))
        return payload

    return _with_temp_content(content, _run)


def normalized_explain(
    *,
    content: str,
    source_type: str,
    input_format: str,
    mapping: Dict[str, Any] | None,
    window_minutes: int,
    index: int,
    first: bool,
    use_ai: bool,
) -> Dict[str, Any]:
    def _run(path: str) -> Dict[str, Any]:
        events, errors = load_normalized_events(
            source_type=source_type,
            path=path,
            input_format=input_format,
            mapping=mapping if source_type == "generic" else None,
        )

        bundles = group_generic_events_to_incident_bundles(
            events,
            window_minutes=window_minutes,
        )

        if not bundles:
            return {
                "source_type": source_type,
                "input_format": input_format,
                "mapping": mapping if source_type == "generic" else None,
                "window_minutes": window_minutes,
                "total_events": len(events),
                "total_incidents": 0,
                "parse_errors": errors,
                "message": "No incidents found for the given source_type and input.",
            }

        selected_index = 0 if first else index
        if selected_index < 0 or selected_index >= len(bundles):
            raise ValueError(
                f"Invalid index {selected_index}. There are {len(bundles)} incident(s)."
            )

        bundle = bundles[selected_index]
        incident = bundle.incident
        evidence = build_normalized_incident_evidence(
            source_type=source_type,
            input_format=input_format,
            window_minutes=window_minutes,
            incident=incident,
            events=bundle.events,
        )

        payload = {
            "source_type": source_type,
            "input_format": input_format,
            "mapping": mapping if source_type == "generic" else None,
            "window_minutes": window_minutes,
            "selected_index": selected_index,
            "incident": incident.to_dict(),
            "incident_evidence": evidence.to_dict(),
            "parse_errors": errors,
        }
        payload.update(_maybe_ai_analysis(evidence, use_ai))
        return payload

    return _with_temp_content(content, _run)