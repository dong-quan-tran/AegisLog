import json
from datetime import datetime, timedelta

from aegislog.incidents import Incident, IncidentTimelineEntry, build_ssh_incident_evidence


def test_build_ssh_incident_evidence_json_serializable():
    start = datetime(2025, 1, 1, 2, 0, 0)

    incident = Incident(
        incident_id="ip:1.2.3.4#0",
        ip="1.2.3.4",
        user="root",
        session_ids=["s1", "s2"],
        total_events=120,
        avg_anomaly_score=0.42,
        auth_failed=110,
        auth_success=1,
        auth_fail_ratio=110 / 111,
        has_success_after_failures=True,
        severity="high",
        severity_reason="failures followed by successful SSH login(s) with elevated anomaly score",
        confidence="high",
        confidence_reason="successful authentication occurred after failed attempts",
        priority="critical",
        priority_score=68,
        priority_reason="priority derived from severity=high and confidence=high (score=68)",
        attack_pattern="possible_compromise",
        attack_pattern_reason="failed SSH authentications followed by successful login(s) for the same source IP",
        primary_user="root",
        targeted_users=["root", "admin"],
        first_seen=start,
        last_seen=start + timedelta(minutes=10),
        auth_failed_streak_max=75,
        auth_burst_max_per_minute=1200,
    )

    timeline = [
        IncidentTimelineEntry(
            timestamp=start,
            session_id="s1",
            ip="1.2.3.4",
            user="root",
            auth_failed=100,
            auth_success=0,
            event_count=100,
            anomaly_score=0.50,
            event_type="failure",
        ),
        IncidentTimelineEntry(
            timestamp=start + timedelta(minutes=5),
            session_id="s2",
            ip="1.2.3.4",
            user="root",
            auth_failed=10,
            auth_success=1,
            event_count=20,
            anomaly_score=0.34,
            event_type="failures_then_success",
        ),
    ]

    evidence = build_ssh_incident_evidence(
        incident,
        timeline,
        log_type="ssh_auth",
        model_type="iforest",
        threshold_percentile=99.0,
    )

    assert evidence.incident_id == "ip:1.2.3.4#0"
    assert evidence.log_type == "ssh_auth"
    assert evidence.model_type == "iforest"
    assert len(evidence.sessions) == 2
    assert evidence.highlights
    assert evidence.extra["auth_failed"] == 110

    payload = evidence.to_dict()
    assert payload["incident_id"] == "ip:1.2.3.4#0"
    assert payload["sessions"][0]["session_id"] == "s1"

    json_text = json.dumps(payload)
    assert isinstance(json_text, str)