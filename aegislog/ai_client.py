import os
from typing import Optional

from openai import OpenAI

from aegislog.ai import LLMIncidentPrompt


class LLMConfigError(RuntimeError):
    pass


def _get_api_key() -> str:
    key = os.getenv("OPENAI_API_KEY")
    if not key:
        raise LLMConfigError(
            "OPENAI_API_KEY is not set. Please export your API key as an "
            "environment variable before using --use-llm."
        )
    return key


def call_llm_for_incident(prompt: LLMIncidentPrompt) -> str:
    """
    Call a real LLM to get an explanation for an incident.

    This uses the OpenAI-compatible client and expects OPENAI_API_KEY
    to be set in the environment.
    """
    api_key = _get_api_key()
    client = OpenAI(api_key=api_key)

    response = client.chat.completions.create(
        model=prompt.model,
        messages=[
            {"role": "user", "content": prompt.prompt},
        ],
        temperature=0.2,
        max_tokens=600,
    )

    return response.choices[0].message.content or ""