from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional


@dataclass
class SessionEvidence:
    """
    Evidence for a single session that participates in an incident.
    Designed to be JSON-serializable via asdict().
    """
    session_id: str
    anomaly_score: float
    start_time: Optional[str]
    end_time: Optional[str]
    ip: Optional[str]
    user: Optional[str]
    auth_failed: int
    auth_success: int
    event_count: int
    event_type: str
    notes: List[str]


@dataclass
class IncidentEvidence:
    """
    High-level evidence object for one incident.
    This is what the explain/JSON flows should consume.
    """
    incident_id: str
    log_type: str
    ip: Optional[str]
    user: Optional[str]
    model_type: str
    feature_version: str
    threshold_percentile: float
    severity: str
    confidence: str
    priority: str
    attack_pattern: str
    highlights: List[str]
    sessions: List[SessionEvidence]
    extra: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)