from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Iterable

import pandas as pd

from aegislog.features.sessions import Session

from aegislog.ml.pipeline import get_model_version



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
    attack_pattern: str
    attack_pattern_reason: str
    primary_user: Optional[str]
    targeted_users: List[str]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    # SSH-focused aggregates
    auth_failed_streak_max: int = 0
    auth_burst_max_per_minute: int = 0


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

    intensity_hint = _describe_auth_intensity(incident)
    description += intensity_hint

    actions = recommend_incident_actions(incident)
    if actions:
        description += " Recommended actions: " + "; ".join(actions) + "."

    return IncidentSummary(
        incident_id=incident.incident_id,
        title=title,
        description=description,
    )


def _classify_attack_pattern(
    auth_failed: int,
    auth_success: int,
    auth_fail_ratio: float,
    targeted_users: List[str],
    has_success_after_failures: bool,
) -> tuple[str, str]:
    """
    Classify SSH attack pattern based on auth behavior and targeted user spread.
    """
    unique_users = len(targeted_users)

    # Possible account compromise: failures then success
    if has_success_after_failures and auth_success > 0:
        return (
            "possible_compromise",
            "failed SSH authentications followed by successful login(s) for the same source IP",
        )

    # Username / password spray: many users, all failures
    if (
        auth_failed >= 100
        and unique_users >= 5
        and auth_success == 0
        and auth_fail_ratio >= 0.9
    ):
        return (
            "password_spray",
            f"high-volume failed SSH authentication attempts ({auth_failed}) against "
            f"{unique_users} distinct user(s) with no successes",
        )

    # Classic brute-force on a small user set
    if auth_failed >= 100 and unique_users <= 3 and auth_fail_ratio >= 0.9:
        return (
            "brute_force",
            f"high-volume failed SSH authentication attempts ({auth_failed}) focused on "
            f"{unique_users} user(s) with very high failure ratio",
        )

    # Low-signal background noise
    if auth_failed < 20 and auth_success == 0:
        return (
            "low_signal",
            "low-volume failed SSH authentication activity without clear brute-force characteristics",
        )

    # Default suspicious auth activity
    return (
        "suspicious_auth_activity",
        "SSH authentication pattern shows some suspicious characteristics but does not match a more specific pattern",
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
    auth_failed_streak_max: int = 0,
    auth_burst_max_per_minute: int = 0,
) -> str:
    """
    Severity uses anomaly score, failed volume/ratio, and SSH intensity indicators.
    """

    # Compromise-like: failures then success, plus decent anomaly and volume
    if has_success_after_failures and avg_anomaly_score >= 0.20 and auth_failed >= 20:
        return "high"

    # Extremely automated behavior: very high volume and intensity
    if (
        auth_failed >= 1000
        and auth_fail_ratio >= 0.95
        and (auth_failed_streak_max >= 200 or auth_burst_max_per_minute >= 500)
    ):
        return "high"

    # Strong brute-force pattern
    if (
        avg_anomaly_score >= 0.25
        and auth_failed >= 500
        and auth_fail_ratio >= 0.90
    ):
        return "high"

    # Elevated, but not extreme
    if (
        avg_anomaly_score >= 0.15
        and auth_failed >= 50
        and auth_fail_ratio >= 0.70
    ):
        return "medium"

    return "low"


def _severity_reason(
    avg_anomaly_score: float,
    auth_failed: int,
    auth_fail_ratio: float,
    has_success_after_failures: bool = False,
    auth_failed_streak_max: int = 0,
    auth_burst_max_per_minute: int = 0,
) -> str:
    if has_success_after_failures and avg_anomaly_score >= 0.20 and auth_failed >= 20:
        return "failures followed by successful SSH login(s) with elevated anomaly score"

    if (
        auth_failed >= 1000
        and auth_fail_ratio >= 0.95
        and (auth_failed_streak_max >= 200 or auth_burst_max_per_minute >= 500)
    ):
        return "extremely high failed-auth volume with intense automated behavior"

    if (
        avg_anomaly_score >= 0.25
        and auth_failed >= 500
        and auth_fail_ratio >= 0.90
    ):
        return "very high failed-auth volume with elevated anomaly score"

    if (
        avg_anomaly_score >= 0.15
        and auth_failed >= 50
        and auth_fail_ratio >= 0.70
    ):
        return "moderate to high failed-auth volume with elevated anomaly score"

    return "limited authentication activity and anomaly score"


def _compute_confidence(
    avg_anomaly_score: float,
    auth_failed: int,
    auth_fail_ratio: float,
    session_count: int,
    has_success_after_failures: bool = False,
    auth_failed_streak_max: int = 0,
    auth_burst_max_per_minute: int = 0,
) -> str:
    """
    Confidence increases with repeated evidence, high volume, and success-after-failures.
    """

    if (
        has_success_after_failures
        or (auth_failed >= 100 and session_count >= 2 and auth_fail_ratio >= 0.90)
        or (avg_anomaly_score >= 0.30 and auth_failed >= 50 and session_count >= 2)
        or auth_failed_streak_max >= 200
        or auth_burst_max_per_minute >= 500
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
    auth_failed_streak_max: int = 0,
    auth_burst_max_per_minute: int = 0,
) -> str:
    if has_success_after_failures:
        return "successful authentication occurred after failed attempts"

    if auth_failed_streak_max >= 200:
        return "very long consecutive failed-auth streak indicating automated guessing"

    if auth_burst_max_per_minute >= 500:
        return "very high SSH event rate consistent with automated attack tooling"

    if auth_failed >= 100 and session_count >= 2 and auth_fail_ratio >= 0.90:
        return "repeated high-volume failed authentications across multiple sessions"

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
                "auth_failed_streak_max": row.get("auth_failed_streak_max", 0),
                "auth_burst_max_per_minute": row.get("auth_burst_max_per_minute", 0),
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

            auth_failed_streak_max = max(
                (s.get("auth_failed_streak_max", 0) for s in cluster),
                default=0,
            )
            auth_burst_max_per_minute = max(
                (s.get("auth_burst_max_per_minute", 0) for s in cluster),
                default=0,
            )

            users = [
                s["user"]
                for s in cluster
                if isinstance(s.get("user"), str) and s["user"]
            ]
            targeted_users = sorted(set(users))
            primary_user = Counter(users).most_common(1)[0][0] if users else None

            has_success_after_failures = total_failed > 0 and total_success > 0

            session_ids = [s["session_id"] for s in cluster]
            timestamps = [s["start_time"] for s in cluster] + [
                s["end_time"] for s in cluster
            ]

            first_seen = min(timestamps) if timestamps else None
            last_seen = max(timestamps) if timestamps else None

            severity = _compute_severity(
                avg_score,
                total_failed,
                auth_fail_ratio,
                has_success_after_failures,
                auth_failed_streak_max=auth_failed_streak_max,
                auth_burst_max_per_minute=auth_burst_max_per_minute,
            )

            reason = _severity_reason(
                avg_score,
                total_failed,
                auth_fail_ratio,
                has_success_after_failures,
                auth_failed_streak_max=auth_failed_streak_max,
                auth_burst_max_per_minute=auth_burst_max_per_minute,
            )

            confidence = _compute_confidence(
                avg_score,
                total_failed,
                auth_fail_ratio,
                len(session_ids),
                has_success_after_failures,
                auth_failed_streak_max=auth_failed_streak_max,
                auth_burst_max_per_minute=auth_burst_max_per_minute,
            )

            confidence_reason = _confidence_reason(
                avg_score,
                total_failed,
                auth_fail_ratio,
                len(session_ids),
                has_success_after_failures,
                auth_failed_streak_max=auth_failed_streak_max,
                auth_burst_max_per_minute=auth_burst_max_per_minute,
            )

            attack_pattern, attack_pattern_reason = _classify_attack_pattern(
                auth_failed=total_failed,
                auth_success=total_success,
                auth_fail_ratio=auth_fail_ratio,
                targeted_users=targeted_users,
                has_success_after_failures=has_success_after_failures,
            )

            priority, priority_score, priority_reason = _compute_priority(
                severity=severity,
                confidence=confidence,
            )

            incident_id = f"ip:{ip}#{cluster_idx}"

            incidents.append(
                Incident(
                    incident_id=incident_id,
                    ip=ip,
                    user=primary_user,
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
                    attack_pattern=attack_pattern,
                    attack_pattern_reason=attack_pattern_reason,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    primary_user=primary_user,
                    targeted_users=targeted_users,
                    auth_failed_streak_max=auth_failed_streak_max,
                    auth_burst_max_per_minute=auth_burst_max_per_minute,
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


def _describe_auth_intensity(incident: Incident) -> str:
    parts: List[str] = []
    if incident.auth_failed_streak_max >= 50:
        parts.append(
            f"maximum consecutive failed attempts reached {incident.auth_failed_streak_max}, "
            "indicating sustained guessing against one or a small set of credentials"
        )
    if incident.auth_burst_max_per_minute >= 1000:
        parts.append(
            f"peak SSH activity reached {incident.auth_burst_max_per_minute} events per minute, "
            "which is consistent with automated attack tooling"
        )
    if not parts:
        return ""
    return " Authentication intensity: " + " ".join(parts) + "."


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

    attack_pattern_counts = Counter(
        getattr(inc, "attack_pattern", None)
        for inc in incidents
        if getattr(inc, "attack_pattern", None)
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
        "attack_pattern_counts": dict(attack_pattern_counts),
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

def build_ssh_incident_evidence(
    incident: Incident,
    timeline: Iterable[IncidentTimelineEntry],
    log_type: str = "ssh_auth",
    model_type: str = "iforest",
    threshold_percentile: float = 99.0,
) -> "IncidentEvidence":
    """
    Build an IncidentEvidence object for an SSH incident, using the existing
    Incident and IncidentTimelineEntry structures.
    """
    from aegislog.incident.evidence import IncidentEvidence, SessionEvidence  # local import to avoid cycles

    session_evidence: List[SessionEvidence] = []

    for entry in timeline:
        notes: List[str] = []

        if entry.auth_failed > 0 and entry.auth_success == 0:
            notes.append("only failed SSH authentications in this session")
        if entry.auth_success > 0 and entry.auth_failed > 0:
            notes.append("failed authentications followed by success in this session")
        if entry.event_count >= 100:
            notes.append("high event volume in this session")

        session_evidence.append(
            SessionEvidence(
                session_id=entry.session_id,
                anomaly_score=entry.anomaly_score,
                start_time=entry.timestamp.isoformat() if entry.timestamp else None,
                end_time=None,  # can be filled later if needed
                ip=entry.ip,
                user=entry.user,
                auth_failed=entry.auth_failed,
                auth_success=entry.auth_success,
                event_count=entry.event_count,
                event_type=entry.event_type,
                notes=notes,
            )
        )

    highlights: List[str] = []

    if incident.has_success_after_failures:
        highlights.append(
            "Failed SSH authentications were followed by successful login(s) from the same IP."
        )
    if incident.auth_failed >= 100 and incident.auth_fail_ratio >= 0.9:
        highlights.append(
            f"High volume of failed SSH authentications ({incident.auth_failed}) with a "
            f"failure ratio of {incident.auth_fail_ratio:.2f}, consistent with brute-force behavior."
        )
    if incident.auth_failed_streak_max >= 50:
        highlights.append(
            f"Maximum consecutive failed attempts reached {incident.auth_failed_streak_max}."
        )
    if incident.auth_burst_max_per_minute >= 1000:
        highlights.append(
            f"Peak SSH event rate reached {incident.auth_burst_max_per_minute} events per minute."
        )
    if not highlights:
        highlights.append("SSH authentication behavior is anomalous but does not match a more specific pattern.")

    extra: Dict[str, Any] = {
        "severity_reason": incident.severity_reason,
        "confidence_reason": incident.confidence_reason,
        "priority_reason": incident.priority_reason,
        "attack_pattern_reason": incident.attack_pattern_reason,
        "auth_failed": incident.auth_failed,
        "auth_success": incident.auth_success,
        "auth_fail_ratio": incident.auth_fail_ratio,
        "total_events": incident.total_events,
        "avg_anomaly_score": incident.avg_anomaly_score,
        "session_count": len(incident.session_ids),
        "first_seen": incident.first_seen.isoformat() if incident.first_seen else None,
        "last_seen": incident.last_seen.isoformat() if incident.last_seen else None,
    }

    evidence = IncidentEvidence(
        incident_id=incident.incident_id,
        log_type=log_type,
        ip=incident.ip,
        user=incident.primary_user,
        model_type=model_type,
        feature_version=get_model_version(),
        threshold_percentile=threshold_percentile,
        severity=incident.severity,
        confidence=incident.confidence,
        priority=incident.priority,
        attack_pattern=incident.attack_pattern,
        highlights=highlights,
        sessions=session_evidence,
        extra=extra,
    )
    return evidence

def build_apache_incident_evidence(
    session: Session,
    session_row: pd.Series,
    *,
    model_type: str = "iforest",
    threshold_percentile: float = 99.0,
) -> "IncidentEvidence":
    from aegislog.incident.evidence import IncidentEvidence, SessionEvidence
    from aegislog.ml.pipeline import get_model_version

    notes: List[str] = []
    highlights: List[str] = []

    status_5xx = int(session_row.get("status_5xx", 0))
    error_events = int(session_row.get("error_events", 0))
    rare_ratio = float(session_row.get("apache_rare_error_message_ratio", 0.0))
    rare_count = int(session_row.get("apache_rare_error_message_count", 0))
    path_ratio = float(session_row.get("apache_rare_path_ratio", 0.0))
    burst_5xx = int(session_row.get("apache_5xx_burst_max_per_minute", 0))
    burst_error = int(session_row.get("apache_error_burst_max_per_minute", 0))
    rare_hour = int(session_row.get("apache_rare_hour", 0))
    anomaly_score = float(session_row.get("anomaly_score", 0.0))

    if status_5xx > 0:
        notes.append(f"{status_5xx} server-error events in this session")
    if error_events > 0:
        notes.append(f"{error_events} error-level Apache events")
    if rare_count > 0:
        notes.append(f"{rare_count} rare error message template(s)")
    if rare_hour:
        notes.append("activity occurred during a rare hour")

    if burst_5xx >= 5:
        highlights.append(
            f"5xx responses were bursty, peaking at {burst_5xx} per minute."
        )
    if burst_error >= 5:
        highlights.append(
            f"Apache error events were bursty, peaking at {burst_error} per minute."
        )
    if rare_ratio > 0:
        highlights.append(
            f"Rare error templates accounted for {rare_ratio:.2f} of observed Apache error messages."
        )
    if path_ratio > 0:
        highlights.append(
            f"Rare paths accounted for {path_ratio:.2f} of distinct path activity."
        )
    if rare_hour:
        highlights.append("The session occurred during an unusual hour for Apache activity.")
    if not highlights:
        highlights.append("Apache behavior was anomalous but without a single dominant indicator.")

    session_ev = SessionEvidence(
        session_id=session.session_id,
        anomaly_score=anomaly_score,
        start_time=session.start_time.isoformat() if session.start_time else None,
        end_time=session.end_time.isoformat() if session.end_time else None,
        ip=session.ip,
        user=session.user,
        auth_failed=0,
        auth_success=0,
        event_count=int(session_row.get("event_count", 0)),
        event_type="apache_session",
        notes=notes,
    )

    extra = {
        "status_5xx": status_5xx,
        "error_events": error_events,
        "notice_events": int(session_row.get("notice_events", 0)),
        "apache_5xx_streak_max": int(session_row.get("apache_5xx_streak_max", 0)),
        "apache_404_burst_max_per_minute": int(session_row.get("apache_404_burst_max_per_minute", 0)),
        "apache_5xx_burst_max_per_minute": burst_5xx,
        "apache_error_burst_max_per_minute": burst_error,
        "apache_distinct_paths": int(session_row.get("apache_distinct_paths", 0)),
        "apache_rare_path_ratio": path_ratio,
        "apache_distinct_message_templates": int(session_row.get("apache_distinct_message_templates", 0)),
        "apache_rare_error_message_count": rare_count,
        "apache_rare_error_message_ratio": rare_ratio,
        "apache_rare_hour": rare_hour,
        "apache_error_vs_notice_ratio": float(session_row.get("apache_error_vs_notice_ratio", 0.0)),
        "apache_high_severity_events": int(session_row.get("apache_high_severity_events", 0)),
        "apache_high_severity_ratio": float(session_row.get("apache_high_severity_ratio", 0.0)),
        "avg_anomaly_score": anomaly_score,
    }

    return IncidentEvidence(
        incident_id=f"apache:{session.session_id}",
        log_type="apache_error",
        ip=session.ip,
        user=session.user,
        model_type=model_type,
        feature_version=get_model_version(),
        threshold_percentile=threshold_percentile,
        severity="medium" if anomaly_score >= 0.15 else "low",
        confidence="medium" if (status_5xx > 0 or rare_count > 0 or burst_error > 0) else "low",
        priority="medium" if anomaly_score >= 0.15 else "low",
        attack_pattern="apache_anomalous_session",
        highlights=highlights,
        sessions=[session_ev],
        extra=extra,
    )