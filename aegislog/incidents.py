from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import pandas as pd

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
    has_success_after_failures: bool
    severity: str
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]


@dataclass
class IncidentSummary:
    incident_id: str
    title: str
    description: str


def recommend_incident_actions(incident: Incident) -> List[str]:
    actions: List[str] = []
    ip = incident.ip or "unknown"

    if incident.auth_failed >= 100 and incident.auth_fail_ratio >= 0.9:
        actions.append(
            f"Block or rate-limit SSH access from source IP {ip} at the firewall or perimeter."
        )
        actions.append(
            "Review authentication logs for the targeted accounts to confirm no unauthorized access occurred."
        )

    if incident.auth_success > 0:
        actions.append(
            "Investigate successful SSH logins during this incident window for signs of account compromise."
        )
        actions.append(
            "Reset credentials and enforce multi-factor authentication on affected accounts if possible."
        )

    if not actions:
        actions.append(
            "Review SSH configuration and authentication policies to ensure best practices are in place."
        )

    return actions


def summarize_incident(incident: Incident) -> IncidentSummary:
    ip = incident.ip or "unknown"
    title = f"{incident.severity.capitalize()} severity SSH incident from {ip}"

    if incident.auth_success > 0 and incident.auth_failed > 0:
        auth_phrase = (
            f"{incident.auth_failed} failed and {incident.auth_success} successful "
            f"SSH authentication attempts"
        )
    elif incident.auth_failed > 0 and incident.auth_success == 0:
        auth_phrase = (
            f"{incident.auth_failed} failed SSH authentication attempts and no successes"
        )
    elif incident.auth_success > 0 and incident.auth_failed == 0:
        auth_phrase = f"{incident.auth_success} successful SSH authentication attempts"
    else:
        auth_phrase = "no SSH authentication activity recorded"

    compromise_hint = ""
    if incident.has_success_after_failures:
        compromise_hint = (
            " Failed authentication activity was followed by one or more successful logins, "
            "which may indicate a successful brute-force attempt or account compromise."
        )
    if (
        incident.auth_failed >= 100
        and incident.auth_success == 0
        and incident.auth_fail_ratio >= 0.9
    ):
        brute_force_hint = (
            " This pattern is consistent with SSH brute-force or password-spraying activity."
        )

    if incident.first_seen and incident.last_seen:
        time_phrase = (
            " This activity was observed between "
            f"{incident.first_seen.isoformat()} and {incident.last_seen.isoformat()}."
        )
    else:
        time_phrase = ""

    description = (
        f"IP {ip} generated {incident.total_events} SSH log events across "
        f"{len(incident.session_ids)} session(s), with {auth_phrase}. "
        f"Authentication failure ratio is {incident.auth_fail_ratio:.2f} and the "
        f"average anomaly score is {incident.avg_anomaly_score:.3f}."
        f"{brute_force_hint}"
        f"{compromise_hint}"
        f"{time_phrase}"
    )

    actions = recommend_incident_actions(incident)
    if actions:
        description += " Recommended actions: " + "; ".join(actions) + "."

    return IncidentSummary(
        incident_id=incident.incident_id,
        title=title,
        description=description,
    )


def _compute_severity(
    avg_anomaly_score: float,
    auth_failed: int,
    auth_fail_ratio: float,
    has_success_after_failures: bool = False,
) -> str:
    if has_success_after_failures and avg_anomaly_score >= 0.20 and auth_failed >= 20:
        return "high"

    # Strong brute-force signal and highly anomalous behavior
    if avg_anomaly_score >= 0.35 and auth_failed >= 500 and auth_fail_ratio >= 0.95:
        return "high"

    # Clear suspicious authentication pattern with elevated anomaly score
    if avg_anomaly_score >= 0.25 and auth_failed >= 200 and auth_fail_ratio >= 0.90:
        return "high"

    # Suspicious but lower-volume activity
    if avg_anomaly_score >= 0.15 and auth_failed >= 50 and auth_fail_ratio >= 0.70:
        return "medium"

    return "low"


def group_sessions_to_incidents(
    sessions: List[Session],
    scores_df: pd.DataFrame,
    min_sessions: int = 1,
    merge_window_minutes: int = 60,
) -> List[Incident]:
    by_key: Dict[tuple[str, str], List[dict]] = defaultdict(list)
    session_by_id: Dict[str, Session] = {s.session_id: s for s in sessions}
    merge_window = timedelta(minutes=merge_window_minutes)

    for _, row in scores_df.iterrows():
        ip = row["ip"]
        user = row.get("user")

        if not isinstance(ip, str) or not ip:
            continue

        user_key = user if isinstance(user, str) and user else ""
        incident_key = (ip, user_key)

        sess = session_by_id.get(row["session_id"])
        if not sess:
            continue

        by_key[incident_key].append(
            {
                "session_id": row["session_id"],
                "event_count": row["event_count"],
                "anomaly_score": row["anomaly_score"],
                "auth_failed": row.get("auth_failed", 0),
                "auth_success": row.get("auth_success", 0),
                "start_time": sess.start_time,
                "end_time": sess.end_time,
            }
        )

    incidents: List[Incident] = []

    for (ip, user_key), sess_list in by_key.items():
        sess_list.sort(key=lambda s: s["start_time"])

        clusters: List[List[dict]] = []
        current_cluster: List[dict] = []

        for sess_info in sess_list:
            if not current_cluster:
                current_cluster = [sess_info]
                continue

            last_end = current_cluster[-1]["end_time"]
            if sess_info["start_time"] - last_end <= merge_window:
                current_cluster.append(sess_info)
            else:
                clusters.append(current_cluster)
                current_cluster = [sess_info]

        if current_cluster:
            clusters.append(current_cluster)

        for cluster_idx, cluster in enumerate(clusters):
            if len(cluster) < min_sessions:
                continue

            total_events = sum(s["event_count"] for s in cluster)
            avg_score = sum(s["anomaly_score"] for s in cluster) / len(cluster)
            total_failed = sum(s["auth_failed"] for s in cluster)
            total_success = sum(s["auth_success"] for s in cluster)
            auth_total = total_failed + total_success
            auth_fail_ratio = total_failed / auth_total if auth_total else 0.0


            has_success_after_failures = total_failed > 0 and total_success > 0
            
            session_ids = [s["session_id"] for s in cluster]
            timestamps = [s["start_time"] for s in cluster] + [s["end_time"] for s in cluster]

            first_seen = min(timestamps) if timestamps else None
            last_seen = max(timestamps) if timestamps else None

            severity = _compute_severity(
                avg_score,
                total_failed,
                auth_fail_ratio,
                has_success_after_failures,
            )
            suffix = f"{ip}|{user_key}" if user_key else ip
            incident_id = f"principal:{suffix}#{cluster_idx}"

            incidents.append(
                Incident(
                    incident_id=incident_id,
                    ip=ip,
                    session_ids=session_ids,
                    total_events=total_events,
                    avg_anomaly_score=avg_score,
                    auth_failed=total_failed,
                    auth_success=total_success,
                    auth_fail_ratio=auth_fail_ratio,
                    severity=severity,
                    first_seen=first_seen,
                    last_seen=last_seen,
                )
            )

    incidents.sort(key=lambda inc: inc.avg_anomaly_score, reverse=True)
    return incidents