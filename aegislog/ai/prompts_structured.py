from __future__ import annotations

from typing import Any, Dict


def build_structured_incident_analysis_prompt(evidence: Any) -> Dict[str, Any]:
    """
    Build a structured prompt payload for AegisLog's AI client.

    The AI client currently expects a dict-like object, not a raw string.
    This payload is intentionally source-agnostic and based only on the
    normalized/generic incident evidence object.
    """
    payload = evidence.to_dict()

    incident = payload.get("incident", {}) or {}
    events = payload.get("events", []) or []

    return {
        "source_type": payload.get("source_type", "unknown"),
        "input_format": payload.get("input_format", "unknown"),
        "window_minutes": payload.get("window_minutes"),
        "incident": incident,
        "events": events,
        "events_sample": events[:20],
        "sampled_event_count": min(len(events), 20),
        "total_event_count": len(events),
        "instructions": {
            "task": (
                "Analyze this grouped log incident conservatively using only the "
                "provided normalized evidence."
            ),
            "response_format": {
                "summary": "short paragraph",
                "evidence": ["bullet 1", "bullet 2"],
                "hypothesis": "short paragraph",
                "caveats": ["caveat 1", "caveat 2"],
                "next_steps": ["step 1", "step 2"],
                "playbook_slug": "short-kebab-case-string-or-empty",
                "playbook_notes": "short paragraph or empty string",
            },
            "rules": [
                "Use only the provided evidence.",
                "Be concise and practical.",
                "Be conservative when evidence is incomplete.",
                "Do not claim confirmed compromise unless strongly supported.",
                "Prefer wording like 'consistent with', 'may indicate', or 'could represent'.",
            ],
        },
    }