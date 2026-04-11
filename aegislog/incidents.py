from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import pandas as pd

from aegislog.features.sessions import Session


@dataclass
class Incident:
    incident_id: str
    ip: Optional[str]
    user: Optional[str]
    session_ids: List[str]
    total_events: int
    avg_anomaly_score: float
    auth_failed: int
    auth_success: int
    auth_fail_ratio: float
    has_success_after_failures: bool
    severity: str
    severity_reason: str
    confidence: str
    confidence_reason: str
    priority: str
    priority_score: int
    priority_reason: str
    primary_user: Optional[str]
    targeted_users: List[str]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]


@dataclass
class IncidentTimelineEntry:
    timestamp: Optional[datetime]
    session_id: str
    ip: Optional[str]
    user: Optional[str]
    auth_failed: int
    auth_success: int
    event_count: int
    anomaly_score: float
    event_type: str


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
    brute_force_hint = ""
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


SEVERITY_TO_SCORE = {"low": 25, "medium": 50, "high": 80}
CONFIDENCE_TO_SCORE = {"low": 30, "medium": 60, "high": 85}

def _compute_priority(
    severity: str,
    confidence: str,
) -> tuple[str, int, str]:
    sev_score = SEVERITY_TO_SCORE.get(severity, 25)
    conf_score = CONFIDENCE_TO_SCORE.get(confidence, 30)

    # Simple multiplicative-style combination inspired by risk scoring
    priority_score = round((sev_score * conf_score) / 100)

    if priority_score >= 68:
        priority = "critical"
    elif priority_score >= 45:
        priority = "high"
    elif priority_score >= 20:
        priority = "medium"
    else:
        priority = "low"

    reason = (
        f"priority derived from severity={severity} "
        f"and confidence={confidence} (score={priority_score})"
    )

    return priority, priority_score, reason


def _compute_severity(
    avg_anomaly_score: float,
    auth_failed: int,
    auth_fail_ratio: float,
    has_success_after_failures: bool = False,
) -> str:
    if has_success_after_failures and avg_anomaly_score >= 0.20 and auth_failed >= 20:
        return "high"

    if avg_anomaly_score >= 0.35 and auth_failed >= 500 and auth_fail_ratio >= 0.95:
        return "high"

    if avg_anomaly_score >= 0.25 and auth_failed >= 200 and auth_fail_ratio >= 0.90:
        return "high"

    if avg_anomaly_score >= 0.15 and auth_failed >= 50 and auth_fail_ratio >= 0.70:
        return "medium"

    return "low"


def _severity_reason(
    avg_anomaly_score: float,
    auth_failed: int,
    auth_fail_ratio: float,
    has_success_after_failures: bool = False,
) -> str:
    if has_success_after_failures and avg_anomaly_score >= 0.20 and auth_failed >= 20:
        return "failures followed by successful SSH login(s)"

    if avg_anomaly_score >= 0.35 and auth_failed >= 500 and auth_fail_ratio >= 0.95:
        return "very high failed-auth volume with high anomaly score"

    if avg_anomaly_score >= 0.25 and auth_failed >= 200 and auth_fail_ratio >= 0.90:
        return "sustained failed-auth pattern with elevated anomaly score"

    if avg_anomaly_score >= 0.15 and auth_failed >= 50 and auth_fail_ratio >= 0.70:
        return "moderate failed-auth volume with elevated anomaly score"

    return "limited authentication activity and anomaly score"


def _compute_confidence(
    avg_anomaly_score: float,
    auth_failed: int,
    auth_fail_ratio: float,
    session_count: int,
    has_success_after_failures: bool = False,
) -> str:
    if (
        has_success_after_failures
        or (auth_failed >= 100 and session_count >= 2 and auth_fail_ratio >= 0.90)
        or (avg_anomaly_score >= 0.30 and auth_failed >= 50 and session_count >= 2)
    ):
        return "high"

    if (
        auth_failed >= 20
        or session_count >= 2
        or avg_anomaly_score >= 0.20
        or auth_fail_ratio >= 0.80
    ):
        return "medium"

    return "low"


def _confidence_reason(
    avg_anomaly_score: float,
    auth_failed: int,
    auth_fail_ratio: float,
    session_count: int,
    has_success_after_failures: bool = False,
) -> str:
    if has_success_after_failures:
        return "successful authentication occurred after failed attempts"

    if auth_failed >= 100 and session_count >= 2 and auth_fail_ratio >= 0.90:
        return "repeated failed authentications across multiple sessions"

    if avg_anomaly_score >= 0.30 and auth_failed >= 50 and session_count >= 2:
        return "elevated anomaly score with repeated suspicious activity"

    if auth_failed >= 20:
        return "moderate volume of failed authentications"

    if session_count >= 2:
        return "activity repeated across multiple sessions"

    if avg_anomaly_score >= 0.20:
        return "anomaly score is elevated but supporting evidence is limited"

    return "limited supporting evidence beyond the base anomaly signal"


def build_incident_timeline(
    incident: Incident,
    sessions: List[Session],
    scores_df: pd.DataFrame,
) -> List[IncidentTimelineEntry]:
    session_by_id: Dict[str, Session] = {s.session_id: s for s in sessions}
    rows = scores_df[scores_df["session_id"].isin(incident.session_ids)]

    timeline: List[IncidentTimelineEntry] = []

    for _, row in rows.iterrows():
        sess = session_by_id.get(row["session_id"])
        if not sess:
            continue

        auth_failed = int(row.get("auth_failed", 0))
        auth_success = int(row.get("auth_success", 0))

        if auth_success > 0 and auth_failed > 0:
            event_type = "failures_then_success"
        elif auth_success > 0:
            event_type = "success"
        elif auth_failed > 0:
            event_type = "failure"
        else:
            event_type = "session"

        timeline.append(
            IncidentTimelineEntry(
                timestamp=sess.start_time,
                session_id=row["session_id"],
                ip=row.get("ip"),
                user=row.get("user"),
                auth_failed=auth_failed,
                auth_success=auth_success,
                event_count=int(row["event_count"]),
                anomaly_score=float(row["anomaly_score"]),
                event_type=event_type,
            )
        )

    timeline.sort(
        key=lambda entry: (
            entry.timestamp is None,
            entry.timestamp,
            entry.session_id,
        )
    )
    return timeline


def group_sessions_to_incidents(
    sessions: List[Session],
    scores_df: pd.DataFrame,
    min_sessions: int = 1,
    merge_window_minutes: int = 60,
) -> List[Incident]:
    by_key: Dict[str, List[dict]] = defaultdict(list)
    session_by_id: Dict[str, Session] = {s.session_id: s for s in sessions}
    merge_window = timedelta(minutes=merge_window_minutes)

    for _, row in scores_df.iterrows():
        ip = row["ip"]
        user = row.get("user")

        if not isinstance(ip, str) or not ip:
            continue

        user_key = user if isinstance(user, str) and user else ""
        incident_key = ip

        sess = session_by_id.get(row["session_id"])
        if not sess:
            continue


        by_key[incident_key].append(
            {
                "session_id": row["session_id"],
                "user": row.get("user"),
                "event_count": row["event_count"],
                "anomaly_score": row["anomaly_score"],
                "auth_failed": row.get("auth_failed", 0),
                "auth_success": row.get("auth_success", 0),
                "start_time": sess.start_time,
                "end_time": sess.end_time,
            }
        )

    incidents: List[Incident] = []

    for ip, sess_list in by_key.items():
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

            users = [
                s["user"]
                for s in cluster
                if isinstance(s.get("user"), str) and s["user"]
            ]
            targeted_users = sorted(set(users))
            primary_user = Counter(users).most_common(1)[0][0] if users else None

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

            reason = _severity_reason(
                avg_score,
                total_failed,
                auth_fail_ratio,
                has_success_after_failures,
            )

            confidence = _compute_confidence(
                avg_score,
                total_failed,
                auth_fail_ratio,
                len(session_ids),
                has_success_after_failures,
            )

            confidence_reason = _confidence_reason(
                avg_score,
                total_failed,
                auth_fail_ratio,
                len(session_ids),
                has_success_after_failures,
            )

            priority, priority_score, priority_reason = _compute_priority(
                severity=severity,
                confidence=confidence,
            )

            suffix = f"{ip}|{user_key}" if user_key else ip
            incident_id = f"ip:{ip}#{cluster_idx}"

            incidents.append(
                Incident(
                    incident_id=incident_id,
                    ip=ip,
                    user=user_key or None,
                    session_ids=session_ids,
                    total_events=total_events,
                    avg_anomaly_score=avg_score,
                    auth_failed=total_failed,
                    auth_success=total_success,
                    auth_fail_ratio=auth_fail_ratio,
                    has_success_after_failures=has_success_after_failures,
                    severity=severity,
                    severity_reason=reason,
                    confidence=confidence,
                    confidence_reason=confidence_reason,
                    priority=priority,
                    priority_score=priority_score,
                    priority_reason=priority_reason,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    primary_user=primary_user,
                    targeted_users=targeted_users,
                )
            )

    severity_rank = {"high": 3, "medium": 2, "low": 1}

    incidents.sort(
        key=lambda inc: (
            severity_rank.get(inc.severity, 0),
            inc.avg_anomaly_score,
        ),
        reverse=True,
    ) 
    return incidents


def build_incident_report(
    incidents: List[Incident],
    total_sessions: Optional[int] = None,
    anomalous_sessions: Optional[int] = None,
    top_n: int = 5,
) -> dict:
    severity_counts = Counter(inc.severity for inc in incidents)
    confidence_counts = Counter(
        inc.confidence for inc in incidents if inc.confidence
    )
    priority_counts = Counter(
        getattr(inc, "priority", None)
        for inc in incidents
        if getattr(inc, "priority", None)
    )
    ip_counts = Counter(inc.ip for inc in incidents if inc.ip)

    targeted_user_counts = Counter()
    for inc in incidents:
        for user in getattr(inc, "targeted_users", []) or []:
            targeted_user_counts[user] += 1

    report = {
        "total_incidents": len(incidents),
        "severity_counts": dict(severity_counts),
        "confidence_counts": dict(confidence_counts),
        "priority_counts": dict(priority_counts),
        "top_incident_ips": [
            {"ip": ip, "incident_count": count}
            for ip, count in ip_counts.most_common(top_n)
        ],
        "top_targeted_users": [
            {"user": user, "incident_count": count}
            for user, count in targeted_user_counts.most_common(top_n)
        ],
    }

    if total_sessions is not None:
        report["total_sessions"] = int(total_sessions)

    if anomalous_sessions is not None:
        report["anomalous_sessions"] = int(anomalous_sessions)
        if total_sessions:
            report["anomalous_session_percent"] = round(
                100.0 * anomalous_sessions / total_sessions, 2
            )
        else:
            report["anomalous_session_percent"] = 0.0

    return report