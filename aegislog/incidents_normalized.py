# aegislog/incidents_normalized.py

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence

from aegislog.normalized import NormalizedEvent
from aegislog.incidents_generic import GenericIncident


@dataclass
class NormalizedIncidentEvidence:
    """
    Source-agnostic incident evidence built from normalized events.

    This is what we feed into the generic AI explain prompt.
    """
    source_type: str
    input_format: str
    window_minutes: int
    incident: GenericIncident
    events: List[NormalizedEvent] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_type": self.source_type,
            "input_format": self.input_format,
            "window_minutes": self.window_minutes,
            "incident": self.incident.to_dict(),
            "events": [e.to_dict() for e in self.events],
        }


def build_normalized_incident_evidence(
    source_type: str,
    input_format: str,
    window_minutes: int,
    incident: GenericIncident,
    events: Sequence[NormalizedEvent],
) -> NormalizedIncidentEvidence:
    """
    Build normalized incident evidence from an incident and its events.

    This intentionally only sees the normalized fields, not the original
    source-specific models, so prompts remain generic.
    """
    return NormalizedIncidentEvidence(
        source_type=source_type,
        input_format=input_format,
        window_minutes=window_minutes,
        incident=incident,
        events=list(events),
    )