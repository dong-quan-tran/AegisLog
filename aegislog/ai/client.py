from __future__ import annotations

from typing import Any, Dict, List, Optional, TypedDict

from aegislog.ai.playbooks import Playbook, lookup_playbook


class LLMError(Exception):
    """Raised when AI analysis cannot be produced or validated."""


REQUIRED_KEYS = [
    "summary",
    "evidence",
    "hypothesis",
    "caveats",
    "next_steps",
    "playbook_slug",
    "playbook_notes",
]


class IncidentAIAnalysis(TypedDict):
    summary: str
    evidence: List[str]
    hypothesis: str
    caveats: List[str]
    next_steps: List[str]
    playbook_slug: Optional[str]
    playbook_notes: Optional[str]


def generate_incident_analysis(prompt: Dict[str, Any]) -> IncidentAIAnalysis:
    """
    Core AI entrypoint for incident analysis.

    For now this uses a deterministic mock backend that constructs a
    structured explanation from the prompt and playbooks. Later, this
    function can route to a real LLM (Gemini, DeepSeek, etc.) while
    keeping the same return shape.
    """
    analysis = _mock_incident_analysis(prompt)
    return validate_ai_analysis(analysis)


def validate_ai_analysis(payload: Dict[str, Any]) -> IncidentAIAnalysis:
    """
    Validate that the AI analysis payload matches the expected schema.

    Ensures all required keys are present and of the correct basic type.
    Raises LLMError if the payload is malformed.
    """
    if not isinstance(payload, dict):
        raise LLMError("AI analysis must be a dict.")

    for key in REQUIRED_KEYS:
        if key not in payload:
            raise LLMError(f"AI analysis is missing required key: {key!r}")

    if not isinstance(payload["summary"], str):
        raise LLMError("AI analysis 'summary' must be a string.")
    if not isinstance(payload["evidence"], list):
        raise LLMError("AI analysis 'evidence' must be a list of strings.")
    if not all(isinstance(item, str) for item in payload["evidence"]):
        raise LLMError("AI analysis 'evidence' must contain only strings.")

    if not isinstance(payload["hypothesis"], str):
        raise LLMError("AI analysis 'hypothesis' must be a string.")
    if not isinstance(payload["caveats"], list):
        raise LLMError("AI analysis 'caveats' must be a list of strings.")
    if not all(isinstance(item, str) for item in payload["caveats"]):
        raise LLMError("AI analysis 'caveats' must contain only strings.")

    if not isinstance(payload["next_steps"], list):
        raise LLMError("AI analysis 'next_steps' must be a list of strings.")
    if not all(isinstance(item, str) for item in payload["next_steps"]):
        raise LLMError("AI analysis 'next_steps' must contain only strings.")

    if payload["playbook_slug"] is not None and not isinstance(
        payload["playbook_slug"], str
    ):
        raise LLMError("AI analysis 'playbook_slug' must be a string or None.")

    if payload["playbook_notes"] is not None and not isinstance(
        payload["playbook_notes"], str
    ):
        raise LLMError("AI analysis 'playbook_notes' must be a string or None.")

    return IncidentAIAnalysis(
        summary=payload["summary"],
        evidence=payload["evidence"],
        hypothesis=payload["hypothesis"],
        caveats=payload["caveats"],
        next_steps=payload["next_steps"],
        playbook_slug=payload["playbook_slug"],
        playbook_notes=payload["playbook_notes"],
    )


def _mock_incident_analysis(prompt: Dict[str, Any]) -> IncidentAIAnalysis:
    """
    Deterministic, provider-free implementation of incident analysis.

    This is intentionally simple and cheap: it inspects the structured
    prompt, chooses a playbook, and generates a short explanation that
    a real LLM could later refine.
    """
    incident = prompt.get("incident", {}) or {}
    evidence = prompt.get("evidence", {}) or {}
    timeline_summary = prompt.get("timeline_summary", "") or ""
    aggregates = prompt.get("aggregates", {}) or {}

    attack_pattern = str(incident.get("attack_pattern") or "low_signal")
    severity = str(incident.get("severity") or "low")

    playbook = lookup_playbook(attack_pattern, severity)

    summary = _build_summary(incident, timeline_summary, playbook)
    evidence_bullets = _build_evidence_bullets(incident, evidence)
    hypothesis = _build_hypothesis(attack_pattern, severity, playbook)
    caveats = _build_caveats(incident, aggregates)
    next_steps = _build_next_steps(playbook)

    playbook_slug: Optional[str] = playbook.slug if playbook else None
    playbook_notes: Optional[str] = (
        playbook.description
        if playbook
        else "No specific playbook matched; using generic guidance."
    )

    return IncidentAIAnalysis(
        summary=summary,
        evidence=evidence_bullets,
        hypothesis=hypothesis,
        caveats=caveats,
        next_steps=next_steps,
        playbook_slug=playbook_slug,
        playbook_notes=playbook_notes,
    )


def _build_summary(
    incident: Dict[str, Any],
    timeline_summary: str,
    playbook: Optional[Playbook],
) -> str:
    ip = incident.get("ip") or "unknown IP"
    severity = incident.get("severity") or "unknown"
    attack_pattern = incident.get("attack_pattern") or "unknown pattern"
    primary_user = incident.get("primary_user") or "unknown user"

    base = (
        f"This incident involves SSH activity for {primary_user} from {ip}, "
        f"classified as {severity} severity with attack pattern '{attack_pattern}'."
    )

    if playbook is not None:
        base += f" It aligns most closely with the playbook '{playbook.title}'."

    if timeline_summary:
        base += " " + timeline_summary

    return base


def _build_evidence_bullets(
    incident: Dict[str, Any],
    evidence: Dict[str, Any],
) -> List[str]:
    bullets: List[str] = []

    total_events = incident.get("total_events")
    auth_failed = incident.get("auth_failed")
    auth_success = incident.get("auth_success")
    auth_fail_ratio = incident.get("auth_fail_ratio")
    auth_burst = incident.get("auth_burst_max_per_minute")
    fail_streak = incident.get("auth_failed_streak_max")

    if total_events is not None:
        bullets.append(
            f"Total SSH authentication events in this incident: {total_events}."
        )
    if auth_failed is not None and auth_success is not None:
        bullets.append(
            f"Observed {auth_failed} failed and {auth_success} successful SSH authentication attempts."
        )
    if auth_fail_ratio is not None:
        bullets.append(
            f"Authentication failure ratio is approximately {auth_fail_ratio:.2f}."
        )
    if fail_streak is not None and fail_streak > 0:
        bullets.append(f"Maximum consecutive failed logins: {fail_streak}.")
    if auth_burst is not None and auth_burst > 0:
        bullets.append(
            f"Maximum failed-login burst in a one-minute window: {auth_burst} events."
        )

    highlights = evidence.get("highlights") or []
    if isinstance(highlights, list) and highlights:
        bullets.append("Evidence highlights:")
        for h in highlights[:3]:
            bullets.append(f"- {h}")

    return bullets


def _build_hypothesis(
    attack_pattern: str,
    severity: str,
    playbook: Optional[Playbook],
) -> str:
    if playbook is not None:
        return (
            f"The activity is most consistent with '{playbook.title}', "
            f"suggesting {playbook.description.lower()}"
        )

    if attack_pattern == "brute_force":
        return (
            "The pattern of repeated authentication failures suggests a brute-force "
            "attempt against one or more accounts."
        )
    if attack_pattern == "password_spray":
        return (
            "The distribution of failures across many accounts suggests password spraying "
            "or credential stuffing."
        )
    if attack_pattern == "possible_compromise":
        return (
            "The combination of failures followed by a successful login suggests a possible "
            "account compromise."
        )

    return (
        "The activity appears to be low-signal background noise or routine probing, "
        "but should still be monitored for escalation."
    )


def _build_caveats(
    incident: Dict[str, Any],
    aggregates: Dict[str, Any],
) -> List[str]:
    caveats: List[str] = []

    total_incidents = aggregates.get("total_incidents")
    if total_incidents is not None and total_incidents < 3:
        caveats.append(
            "Overall incident volume is low in the aggregate data, so severity estimates "
            "may be less stable."
        )

    if incident.get("ip") is None:
        caveats.append(
            "Source IP is unknown in this incident, which limits attribution and correlation."
        )

    if incident.get("primary_user") is None:
        caveats.append(
            "The primary user associated with this activity could not be determined, "
            "which limits user-focused investigation steps."
        )

    caveats.append(
        "This analysis is based solely on SSH authentication patterns and does not include "
        "full process, file, or network telemetry."
    )

    return caveats


def _build_next_steps(playbook: Optional[Playbook]) -> List[str]:
    if playbook is not None and playbook.next_steps:
        return list(playbook.next_steps)

    return [
        "Review detailed logs for the affected host(s) around the time of this incident.",
        "Confirm whether any high-value accounts were successfully accessed during the incident window.",
        "If anything suspicious is confirmed, rotate credentials and keys for affected accounts.",
        "Increase monitoring on the affected host(s) and consider tightening SSH access controls.",
    ]