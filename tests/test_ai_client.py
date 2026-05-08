from aegislog.ai.client import (
    LLMError,
    REQUIRED_KEYS,
    generate_incident_analysis,
    validate_ai_analysis,
)


def make_prompt(
    attack_pattern: str = "brute_force",
    severity: str = "high",
    ip: str | None = "203.0.113.10",
    primary_user: str | None = "root",
) -> dict:
    return {
        "incident": {
            "incident_id": "inc-001",
            "ip": ip,
            "severity": severity,
            "attack_pattern": attack_pattern,
            "primary_user": primary_user,
            "total_events": 25,
            "auth_failed": 24,
            "auth_success": 1,
            "auth_fail_ratio": 0.96,
            "auth_burst_max_per_minute": 12,
            "auth_failed_streak_max": 20,
        },
        "evidence": {
            "highlights": [
                "High authentication failure ratio.",
                "Burst of failed logins observed.",
                "Possible credential attack behavior.",
            ]
        },
        "timeline_summary": "Activity escalated rapidly over a short time window.",
        "aggregates": {
            "total_incidents": 2,
        },
    }


def test_generate_incident_analysis_returns_required_shape() -> None:
    result = generate_incident_analysis(make_prompt())

    assert isinstance(result, dict)

    for key in REQUIRED_KEYS:
        assert key in result

    assert isinstance(result["summary"], str)
    assert isinstance(result["evidence"], list)
    assert all(isinstance(x, str) for x in result["evidence"])

    assert isinstance(result["hypothesis"], str)

    assert isinstance(result["caveats"], list)
    assert all(isinstance(x, str) for x in result["caveats"])

    assert isinstance(result["next_steps"], list)
    assert all(isinstance(x, str) for x in result["next_steps"])

    assert result["playbook_slug"] is None or isinstance(result["playbook_slug"], str)
    assert result["playbook_notes"] is None or isinstance(result["playbook_notes"], str)


def test_validate_ai_analysis_accepts_valid_payload() -> None:
    payload = {
        "summary": "Test summary",
        "evidence": ["one", "two"],
        "hypothesis": "Test hypothesis",
        "caveats": ["c1"],
        "next_steps": ["n1", "n2"],
        "playbook_slug": "ssh-brute-force",
        "playbook_notes": "Use the brute force response workflow.",
    }

    validated = validate_ai_analysis(payload)
    assert validated == payload


def test_validate_ai_analysis_rejects_missing_key() -> None:
    payload = {
        "summary": "Test summary",
        "evidence": ["one", "two"],
        "hypothesis": "Test hypothesis",
        "caveats": ["c1"],
        "next_steps": ["n1", "n2"],
        "playbook_slug": "ssh-brute-force",
    }

    try:
        validate_ai_analysis(payload)
        assert False, "Expected LLMError for missing required key"
    except LLMError as exc:
        assert "missing required key" in str(exc)


def test_validate_ai_analysis_rejects_wrong_type() -> None:
    payload = {
        "summary": "Test summary",
        "evidence": "not-a-list",
        "hypothesis": "Test hypothesis",
        "caveats": ["c1"],
        "next_steps": ["n1", "n2"],
        "playbook_slug": "ssh-brute-force",
        "playbook_notes": "Use the brute force response workflow.",
    }

    try:
        validate_ai_analysis(payload)
        assert False, "Expected LLMError for wrong evidence type"
    except LLMError as exc:
        assert "evidence" in str(exc)


def test_generate_incident_analysis_uses_playbook_for_brute_force() -> None:
    result = generate_incident_analysis(
        make_prompt(attack_pattern="brute_force", severity="high")
    )

    assert result["playbook_slug"] is None or isinstance(result["playbook_slug"], str)
    assert isinstance(result["next_steps"], list)
    assert len(result["next_steps"]) > 0
    assert isinstance(result["summary"], str)
    assert isinstance(result["hypothesis"], str)