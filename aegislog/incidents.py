from dataclasses import dataclass
from typing import List, Optional

import pandas as pd
from collections import defaultdict

from aegislog.features.sessions import Session

@dataclass
class Incident:
    incident_id: str
    ip: Optional[str]
    session_ids: List[str]
    total_events: int
    avg_anomaly_score: float
    auth_failed: int
    auth_success: int
    auth_fail_ratio: float
    severity: str  # e.g. "low" | "medium" | "high"

def _compute_severity(
    avg_anomaly_score: float,
    auth_failed: int,
    auth_fail_ratio: float,
) -> str:
    # Simple heuristic just to start; you can tune later.
    if auth_failed >= 1000 and auth_fail_ratio >= 0.9 and avg_anomaly_score >= 0.25:
        return "high"
    if auth_failed >= 200 and auth_fail_ratio >= 0.7 and avg_anomaly_score >= 0.15:
        return "medium"
    return "low"

def group_sessions_by_ip(
    sessions: list[Session],
    scores_df: pd.DataFrame,
    min_sessions: int = 1,
) -> list[Incident]:
    by_ip: dict[str, list[dict]] = defaultdict(list)

    for _, row in scores_df.iterrows():
        ip = row["ip"]
        if not isinstance(ip, str) or not ip:
            continue
        by_ip[ip].append(
            {
                "session_id": row["session_id"],
                "event_count": row["event_count"],
                "anomaly_score": row["anomaly_score"],
                "auth_failed": row.get("auth_failed", 0),
                "auth_success": row.get("auth_success", 0),
            }
        )

    incidents: list[Incident] = []
    for idx, (ip, sess_list) in enumerate(by_ip.items()):
        if len(sess_list) < min_sessions:
            continue

        total_events = sum(s["event_count"] for s in sess_list)
        avg_score = (
            sum(s["anomaly_score"] for s in sess_list) / len(sess_list)
            if sess_list
            else 0.0
        )
        total_failed = sum(s["auth_failed"] for s in sess_list)
        total_success = sum(s["auth_success"] for s in sess_list)
        auth_total = total_failed + total_success
        auth_fail_ratio = total_failed / auth_total if auth_total else 0.0

        incident_id = f"ip:{ip}#{idx}"
        
        severity = _compute_severity(avg_score, total_failed, auth_fail_ratio)

        incidents.append(
            Incident(
                incident_id=incident_id,
                ip=ip,
                session_ids=[s["session_id"] for s in sess_list],
                total_events=total_events,
                avg_anomaly_score=avg_score,
                auth_failed=total_failed,
                auth_success=total_success,
                auth_fail_ratio=auth_fail_ratio,
                severity=severity,
            )
        )

    incidents.sort(key=lambda inc: inc.avg_anomaly_score, reverse=True)
    return incidents
