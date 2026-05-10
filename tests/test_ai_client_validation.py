import pytest

from aegislog.ai.client import LLMError, validate_ai_analysis


def test_validate_ai_analysis_accepts_valid_payload() -> None:
    payload = {
        "summary": "Suspicious SSH behavior detected.",
        "evidence": ["Repeated failed logins", "Single eventual success"],
        "hypothesis": "Possible brute-force compromise.",
        "caveats": ["Single-host visibility only"],
        "next_steps": ["Rotate credentials", "Review host logs"],
        "playbook_slug": "ssh_brute_force",
        "playbook_notes": "Standard SSH brute-force response steps.",
    }

    result = validate_ai_analysis(payload)

    assert result["summary"] == payload["summary"]
    assert result["evidence"] == payload["evidence"]
    assert result["hypothesis"] == payload["hypothesis"]
    assert result["caveats"] == payload["caveats"]
    assert result["next_steps"] == payload["next_steps"]
    assert result["playbook_slug"] == "ssh_brute_force"


def test_validate_ai_analysis_rejects_missing_required_key() -> None:
    payload = {
        "summary": "Suspicious SSH behavior detected.",
        "evidence": ["Repeated failed logins"],
        "hypothesis": "Possible brute-force compromise.",
        "caveats": ["Single-host visibility only"],
        "next_steps": ["Rotate credentials"],
        "playbook_slug": "ssh_brute_force",
    }

    with pytest.raises(LLMError, match="missing required key"):
        validate_ai_analysis(payload)


def test_validate_ai_analysis_rejects_non_dict_payload() -> None:
    with pytest.raises(LLMError, match="must be a dict"):
        validate_ai_analysis(["not", "a", "dict"])


def test_validate_ai_analysis_rejects_wrong_evidence_type() -> None:
    payload = {
        "summary": "Suspicious SSH behavior detected.",
        "evidence": "Repeated failed logins",
        "hypothesis": "Possible brute-force compromise.",
        "caveats": ["Single-host visibility only"],
        "next_steps": ["Rotate credentials"],
        "playbook_slug": "ssh_brute_force",
        "playbook_notes": "Standard SSH brute-force response steps.",
    }

    with pytest.raises(LLMError, match="evidence"):
        validate_ai_analysis(payload)


def test_validate_ai_analysis_rejects_non_string_evidence_items() -> None:
    payload = {
        "summary": "Suspicious SSH behavior detected.",
        "evidence": ["Repeated failed logins", 123],
        "hypothesis": "Possible brute-force compromise.",
        "caveats": ["Single-host visibility only"],
        "next_steps": ["Rotate credentials"],
        "playbook_slug": "ssh_brute_force",
        "playbook_notes": "Standard SSH brute-force response steps.",
    }

    with pytest.raises(LLMError, match="evidence"):
        validate_ai_analysis(payload)


def test_validate_ai_analysis_rejects_non_string_optional_fields() -> None:
    payload = {
        "summary": "Suspicious SSH behavior detected.",
        "evidence": ["Repeated failed logins"],
        "hypothesis": "Possible brute-force compromise.",
        "caveats": ["Single-host visibility only"],
        "next_steps": ["Rotate credentials"],
        "playbook_slug": 123,
        "playbook_notes": None,
    }

    with pytest.raises(LLMError, match="playbook_slug"):
        validate_ai_analysis(payload)