from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from typing import Any, Dict, Iterable, Optional

from aegislog.incidents import Incident, IncidentTimelineEntry
from aegislog.incident.evidence import IncidentEvidence


def _iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    return dt.isoformat()


def summarize_timeline(timeline: Iterable[IncidentTimelineEntry]) -> str:
    """
    Produce a short, human-readable summary of the incident timeline.

    This is intentionally simple for now; it can be refined later without
    breaking the AI integration contract.
    """
    entries = list(timeline)
    if not entries:
        return "No timeline entries available for this incident."

    entries_sorted = sorted(entries, key=lambda e: e.timestamp or datetime.min)
    first = entries_sorted[0]
    last = entries_sorted[-1]

    total_events = sum(e.event_count for e in entries_sorted)
    total_failed = sum(e.auth_failed for e in entries_sorted)
    total_success = sum(e.auth_success for e in entries_sorted)

    ip = first.ip or "unknown IP"
    user = first.user or "unknown user"

    parts: list[str] = []

    parts.append(
        f"Incident activity spans from {first.timestamp.isoformat()} "
        f"to {last.timestamp.isoformat()} for user {user} from {ip}."
    )

    parts.append(
        f"Across all sessions, there were {total_events} SSH authentication events "
        f"with {total_failed} failures and {total_success} successes."
    )

    if total_failed > 0 and total_success == 0:
        parts.append(
            "Only failed SSH authentication attempts were observed; no successful logins."
        )
    elif total_failed > 0 and total_success > 0:
        parts.append(
            "Failed SSH authentication attempts were followed by at least one successful login."
        )
    elif total_failed == 0 and total_success > 0:
        parts.append("Only successful SSH authentication events were observed.")

    return " ".join(parts)


def build_incident_prompt(
    incident: Incident,
    evidence: IncidentEvidence,
    timeline: Iterable[IncidentTimelineEntry],
    report: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build a structured prompt dict for AI incident analysis (SSH-focused).

    The returned structure is provider-agnostic and is intended to be consumed
    by aegislog.ai.client.generate_incident_analysis().
    """
    timeline_text = summarize_timeline(timeline)

    # Basic aggregates – fall back to minimal values if no report is provided.
    aggregates: Dict[str, Any] = {
        "total_sessions": None,
        "total_incidents": None,
        "severity_counts": {},
        "attack_pattern_counts": {},
    }

    if report is not None:
        aggregates["total_sessions"] = report.get("total_sessions")
        aggregates["total_incidents"] = report.get("total_incidents")
        aggregates["severity_counts"] = report.get("severity_counts", {})
        aggregates["attack_pattern_counts"] = report.get("attack_pattern_counts", {})

    # Some callers may pass IncidentEvidence built from different contexts,
    # but for SSH we assume the default log_type/model_type are already set.
    evidence_payload = evidence.to_dict()

    prompt: Dict[str, Any] = {
        "incident": {
            "id": incident.incident_id,
            "ip": incident.ip,
            "severity": incident.severity,
            "severity_reason": incident.severity_reason,
            "confidence": incident.confidence,
            "confidence_reason": incident.confidence_reason,
            "priority": incident.priority,
            "priority_score": incident.priority_score,
            "priority_reason": incident.priority_reason,
            "attack_pattern": incident.attack_pattern,
            "attack_pattern_reason": incident.attack_pattern_reason,
            "primary_user": incident.primary_user,
            "targeted_users": list(incident.targeted_users or []),
            "total_events": incident.total_events,
            "auth_failed": incident.auth_failed,
            "auth_success": incident.auth_success,
            "auth_fail_ratio": incident.auth_fail_ratio,
            "auth_failed_streak_max": incident.auth_failed_streak_max,
            "auth_burst_max_per_minute": incident.auth_burst_max_per_minute,
            "first_seen": _iso(incident.first_seen),
            "last_seen": _iso(incident.last_seen),
        },
        "evidence": evidence_payload,
        "timeline_summary": timeline_text,
        "aggregates": aggregates,
        "instructions": {
            "goal": (
                "Explain this SSH incident to a junior security engineer, "
                "highlighting behavior, risk, and practical response steps."
            ),
            "audience": (
                "Junior security engineer with basic SSH, Linux, and authentication knowledge."
            ),
            "style": (
                "Short, clear, and practical. Use neutral, professional tone. "
                "Avoid overly verbose or speculative language."
            ),
            "length": (
                "Aim for one or two short paragraphs in the summary, "
                "plus concise bullet lists for evidence, caveats, and next steps."
            ),
        },
    }

    return prompt