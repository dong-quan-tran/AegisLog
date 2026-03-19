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
    
def group_sessions_by_ip(
    sessions: list[Session],
    scores_df: pd.DataFrame,
    min_sessions: int = 1,
) -> list[Incident]:
    # scores_df must have columns: session_id, ip, event_count, anomaly_score
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
        incident_id = f"ip:{ip}#{idx}"
        incidents.append(
            Incident(
                incident_id=incident_id,
                ip=ip,
                session_ids=[s["session_id"] for s in sess_list],
                total_events=total_events,
                avg_anomaly_score=avg_score,
            )
        )

    # Sort by avg anomaly score descending
    incidents.sort(key=lambda inc: inc.avg_anomaly_score, reverse=True)
    return incidents
