from dataclasses import dataclass
from typing import Optional

from aegislog.incidents import Incident, IncidentSummary


@dataclass
class LLMIncidentPrompt:
    incident_id: str
    model: str
    prompt: str


def build_incident_llm_prompt(
    incident: Incident,
    summary: IncidentSummary,
    model: str = "gpt-4.1-mini",
) -> LLMIncidentPrompt:
    ip = incident.ip or "unknown"

    if incident.first_seen and incident.last_seen:
        time_lines = (
            f"- First seen: {incident.first_seen.isoformat()}\n"
            f"- Last seen: {incident.last_seen.isoformat()}\n"
        )
    else:
        time_lines = ""

    prompt = f"""You are a security analyst AI assistant.

You are investigating a suspicious SSH security incident.

Here is structured information about the incident:

- Incident ID: {incident.incident_id}
- Source IP: {ip}
- Severity: {incident.severity}
- Total SSH log events: {incident.total_events}
- Number of SSH sessions: {len(incident.session_ids)}
- Failed authentication attempts: {incident.auth_failed}
- Successful authentication attempts: {incident.auth_success}
- Authentication failure ratio: {incident.auth_fail_ratio:.2f}
- Average anomaly score: {incident.avg_anomaly_score:.3f}
{time_lines}Here is an existing summary of the incident:

Title: {summary.title}
Description: {summary.description}

Task:
1. Briefly explain what is happening in this incident in 2–3 sentences.
2. Indicate whether the pattern is consistent with SSH brute-force or password-spraying activity.
3. Suggest one or two high-level next steps an on-call engineer or SOC analyst should consider.

Use clear, concise language suitable for a junior security engineer."""
    return LLMIncidentPrompt(
        incident_id=incident.incident_id,
        model=model,
        prompt=prompt,
    )


def explain_incident_with_llm(prompt: LLMIncidentPrompt) -> str:
    """
    Placeholder for future LLM integration.

    For now, this just returns the prompt text so it can be inspected or sent
    to an external LLM client by the caller.
    """
    return prompt.prompt