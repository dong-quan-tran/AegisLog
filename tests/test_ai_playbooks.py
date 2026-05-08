from aegislog.ai.playbooks import Playbook, lookup_playbook


def test_lookup_playbook_returns_exact_match_for_possible_compromise_high() -> None:
    result = lookup_playbook("possible_compromise", "high")

    assert result is not None
    assert isinstance(result, Playbook)
    assert result.slug == "ssh_possible_compromise_high"
    assert "likely account compromise" in result.description.lower()
    assert len(result.next_steps) > 0


def test_lookup_playbook_returns_exact_match_for_brute_force_medium() -> None:
    result = lookup_playbook("brute_force", "medium")

    assert result is not None
    assert result.slug == "ssh_bruteforce_medium"
    assert "brute-force" in result.title.lower()
    assert len(result.next_steps) > 0


def test_lookup_playbook_falls_back_to_medium_for_brute_force_high() -> None:
    result = lookup_playbook("brute_force", "high")

    assert result is not None
    assert result.slug == "ssh_bruteforce_medium"
    assert len(result.next_steps) > 0


def test_lookup_playbook_falls_back_to_medium_for_password_spray_low() -> None:
    result = lookup_playbook("password_spray", "low")

    assert result is not None
    assert result.slug == "ssh_password_spray_medium"
    assert "password spraying" in result.description.lower()
    assert len(result.next_steps) > 0


def test_lookup_playbook_returns_exact_match_for_low_signal_low() -> None:
    result = lookup_playbook("low_signal", "low")

    assert result is not None
    assert result.slug == "ssh_low_signal_background"
    assert len(result.next_steps) > 0


def test_lookup_playbook_returns_none_for_unknown_pattern() -> None:
    result = lookup_playbook("totally_unknown_pattern", "high")

    assert result is None


def test_lookup_playbook_returns_none_when_no_exact_or_medium_fallback_exists() -> None:
    result = lookup_playbook("possible_compromise", "low")

    assert result is None


def test_lookup_playbook_returns_apache_placeholder_playbook() -> None:
    result = lookup_playbook("apache_error_spike", "medium")

    assert result is not None
    assert result.slug == "apache_error_spike_medium"
    assert "apache error spike" in result.title.lower()
    assert len(result.next_steps) > 0