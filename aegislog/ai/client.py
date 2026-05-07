from typing import Any, Dict

class LLMError(Exception):
    pass


def generate_incident_analysis(prompt: Dict[str, Any]) -> Dict[str, Any]:
    """
    Core AI entrypoint. For now, this can:
    - call a real free-tier API (Gemini, DeepSeek) if env vars/API key present, or
    - fall back to a deterministic mock that returns a canned analysis based on attack_pattern/severity.
    """
    backend = _detect_backend()
    if backend == "mock":
        return _mock_incident_analysis(prompt)
    elif backend == "gemini":
        return _call_gemini(prompt)
    elif backend == "deepseek":
        return _call_deepseek(prompt)
    else:
        raise LLMError("No LLM backend configured")