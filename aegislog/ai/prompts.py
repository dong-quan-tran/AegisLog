from __future__ import annotations

from typing import Any, Dict

from aegislog.incident.evidence import IncidentEvidence


def build_incident_analysis_prompt(evidence: IncidentEvidence) -> Dict[str, Any]:
    """
    Convert IncidentEvidence into the normalized prompt shape expected by
    generate_incident_analysis().

    Returned schema:
      {
        "incident": {...},
        "evidence": {...},
        "timeline_summary": str,
        "aggregates": {...},
      }

    This function is intentionally deterministic and provider-agnostic so it
    can be reused by multiple CLIs (SSH, Apache, future log types).
    """
    if evidence.log_type == "apache_error":
        return _build_apache_prompt(evidence)

    if evidence.log_type == "ssh_auth":
        return _build_ssh_prompt(evidence)

    return _build_generic_prompt(evidence)


def _build_apache_prompt(evidence: IncidentEvidence) -> Dict[str, Any]:
    extra = evidence.extra or {}

    incident = {
        "incident_id": evidence.incident_id,
        "ip": evidence.ip,
        "severity": evidence.severity,
        "attack_pattern": evidence.attack_pattern,
        "primary_user": evidence.user,
        "total_events": extra.get("error_events", 0),
        "avg_anomaly_score": extra.get("avg_anomaly_score", 0.0),
        "status_5xx": extra.get("status_5xx", 0),
        "apache_5xx_burst_max_per_minute": extra.get(
            "apache_5xx_burst_max_per_minute", 0
        ),
        "apache_error_burst_max_per_minute": extra.get(
            "apache_error_burst_max_per_minute", 0
        ),
        "apache_rare_error_message_ratio": extra.get(
            "apache_rare_error_message_ratio", 0.0
        ),
        "apache_rare_path_ratio": extra.get("apache_rare_path_ratio", 0.0),
        "apache_high_severity_ratio": extra.get("apache_high_severity_ratio", 0.0),
    }

    evidence_block = {
        "highlights": list(evidence.highlights),
    }

    timeline_summary = (
        f"Apache error session {evidence.incident_id} with attack pattern "
        f"'{evidence.attack_pattern}' and severity {evidence.severity}."
    )

    aggregates = {
        "total_incidents": 1,
    }

    return {
        "incident": incident,
        "evidence": evidence_block,
        "timeline_summary": timeline_summary,
        "aggregates": aggregates,
    }


def _build_ssh_prompt(evidence: IncidentEvidence) -> Dict[str, Any]:
    extra = evidence.extra or {}

    incident = {
        "incident_id": evidence.incident_id,
        "ip": evidence.ip,
        "severity": evidence.severity,
        "attack_pattern": evidence.attack_pattern,
        "primary_user": evidence.user,
        "total_events": extra.get("total_events", 0),
        "avg_anomaly_score": extra.get("avg_anomaly_score", 0.0),
        "auth_failed": extra.get("auth_failed", 0),
        "auth_success": extra.get("auth_success", 0),
        "auth_fail_ratio": extra.get("auth_fail_ratio", 0.0),
        "auth_failed_streak_max": extra.get("auth_failed_streak_max", 0),
        "auth_burst_max_per_minute": extra.get("auth_burst_max_per_minute", 0),
        "first_seen": extra.get("first_seen"),
        "last_seen": extra.get("last_seen"),
    }

    evidence_block = {
        "highlights": list(evidence.highlights),
    }

    timeline_summary = (
        f"SSH incident {evidence.incident_id} with attack pattern "
        f"'{evidence.attack_pattern}' and severity {evidence.severity}."
    )

    aggregates = {
        "total_incidents": 1,
    }

    return {
        "incident": incident,
        "evidence": evidence_block,
        "timeline_summary": timeline_summary,
        "aggregates": aggregates,
    }


def _build_generic_prompt(evidence: IncidentEvidence) -> Dict[str, Any]:
    extra = evidence.extra or {}

    incident = {
        "incident_id": evidence.incident_id,
        "ip": evidence.ip,
        "severity": evidence.severity,
        "attack_pattern": evidence.attack_pattern,
        "primary_user": evidence.user,
        "total_events": extra.get("total_events", 0),
        "avg_anomaly_score": extra.get("avg_anomaly_score", 0.0),
    }

    evidence_block = {
        "highlights": list(evidence.highlights),
    }

    timeline_summary = (
        f"Incident {evidence.incident_id} for log_type '{evidence.log_type}' "
        f"with attack pattern '{evidence.attack_pattern}' and severity {evidence.severity}."
    )

    aggregates = {
        "total_incidents": 1,
    }

    return {
        "incident": incident,
        "evidence": evidence_block,
        "timeline_summary": timeline_summary,
        "aggregates": aggregates,
    }