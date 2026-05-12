from __future__ import annotations

from typing import Any, Dict

from aegislog.incident.evidence import IncidentEvidence


def build_incident_analysis_prompt(evidence: IncidentEvidence) -> Dict[str, Any]:
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
        "error_count": extra.get("error_count", 0),
        "warning_count": extra.get("warning_count", 0),
        "distinct_users": extra.get("distinct_users", 0),
        "distinct_hosts": extra.get("distinct_hosts", 0),
        "distinct_src_ips": extra.get("distinct_src_ips", 0),
        "group_key": extra.get("group_key"),
        "source_type": extra.get("source_type"),
        "first_seen": extra.get("first_seen"),
        "last_seen": extra.get("last_seen"),
        "summary_title": extra.get("summary_title"),
        "summary_description": extra.get("summary_description"),
    }

    evidence_block = {
        "highlights": list(evidence.highlights),
        "sample_events": list(extra.get("sample_events", [])),
    }

    timeline_summary = (
        f"Generic incident {evidence.incident_id} for log_type '{evidence.log_type}' "
        f"with attack pattern '{evidence.attack_pattern}' and severity {evidence.severity}."
    )

    aggregates = {
        "total_incidents": 1,
        "input_format": extra.get("input_format"),
        "window_minutes": extra.get("window_minutes"),
    }

    return {
        "incident": incident,
        "evidence": evidence_block,
        "timeline_summary": timeline_summary,
        "aggregates": aggregates,
    }