from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass(frozen=True)
class Playbook:
    slug: str
    title: str
    description: str
    next_steps: List[str]


# Keyed by (attack_pattern, severity)
_PLAYBOOKS: Dict[Tuple[str, str], Playbook] = {
    # SSH: high-severity possible compromise
    ("possible_compromise", "high"): Playbook(
        slug="ssh_possible_compromise_high",
        title="SSH possible compromise (high severity)",
        description=(
            "Multiple failed SSH login attempts followed by a successful login "
            "for a sensitive account. Treat as a likely account compromise until "
            "proven otherwise."
        ),
        next_steps=[
            "Immediately revoke active SSH keys and reset credentials for the affected account(s).",
            "Review all commands and file changes executed during the suspicious session(s).",
            "Search for lateral movement from the source IP and affected account(s) in other logs.",
            "Check for new or modified sudoers entries, cron jobs, startup scripts, or binaries.",
            "Increase monitoring on the affected host(s) and related accounts for at least 24–72 hours.",
        ],
    ),
    # SSH: medium-severity brute-force
    ("brute_force", "medium"): Playbook(
        slug="ssh_bruteforce_medium",
        title="SSH brute-force attempts (medium severity)",
        description=(
            "Sustained SSH authentication failures from one or a few IPs without clear evidence "
            "of a successful compromise."
        ),
        next_steps=[
            "Block or rate-limit the offending IPs at the firewall, security group, or WAF.",
            "Enable or tighten SSH rate limiting and lockout policies for repeated failures.",
            "Verify that password authentication is disabled where possible and prefer SSH keys.",
            "Ensure multi-factor authentication (MFA) is enabled for administrative accounts.",
            "Review recent authentication logs for similar patterns from other source IPs.",
        ],
    ),
    # SSH: password spray / low-cred-stuffing
    ("password_spray", "medium"): Playbook(
        slug="ssh_password_spray_medium",
        title="SSH password spraying / credential stuffing (medium severity)",
        description=(
            "SSH authentication failures distributed across many accounts from one or more IPs, "
            "suggesting password spraying or credential stuffing rather than a targeted brute-force."
        ),
        next_steps=[
            "Identify all accounts targeted by the spray and review their recent activity.",
            "Reset passwords and invalidate sessions for any high-value accounts that were targeted.",
            "Check whether the targeted credentials appear in known breach datasets or password dumps.",
            "Increase monitoring and alerting for repeated failures across multiple accounts.",
            "Consider introducing mandatory MFA for all remote-access users if not already in place.",
        ],
    ),
    # SSH: noisy but low-signal scanning / background noise
    ("low_signal", "low"): Playbook(
        slug="ssh_low_signal_background",
        title="Low-signal SSH noise (low severity)",
        description=(
            "Low-volume SSH authentication noise that does not clearly indicate a focused attack "
            "or successful compromise."
        ),
        next_steps=[
            "Record the source IPs and keep an eye on future activity spikes from the same ranges.",
            "Confirm that SSH configuration follows best practices (non-root login, key-based auth, no password from internet).",
            "Ensure basic network protections are in place (firewall, security groups, or VPN requirements).",
            "If similar patterns become more frequent, revisit thresholds and consider additional controls.",
        ],
    ),
    # Placeholder for Apache-focused patterns (to be filled later)
    ("apache_error_spike", "medium"): Playbook(
        slug="apache_error_spike_medium",
        title="Apache error spike (medium severity)",
        description=(
            "Burst of Apache error events (4xx/5xx) which may indicate scanning, misconfiguration, "
            "or application errors affecting availability."
        ),
        next_steps=[
            "Review the specific error messages and affected endpoints during the spike window.",
            "Check for recent configuration changes or deployments around the time of the spike.",
            "Correlate with access logs to see if the spike is driven by one IP or many clients.",
            "If impact is user-visible, prioritize stabilizing the service and then investigate root cause.",
        ],
    ),
}


def lookup_playbook(attack_pattern: str, severity: str) -> Optional[Playbook]:
    """
    Return the most specific playbook for a given (attack_pattern, severity) pair.

    If no exact match is found, this can be extended later to fall back to a
    pattern-only or severity-only default. For now, it returns None on miss.
    """
    key = (attack_pattern, severity)
    if key in _PLAYBOOKS:
        return _PLAYBOOKS[key]

    # Simple fallback: try pattern with "medium" severity if a specific severity is missing.
    if severity != "medium":
        fallback_key = (attack_pattern, "medium")
        if fallback_key in _PLAYBOOKS:
            return _PLAYBOOKS[fallback_key]

    return None