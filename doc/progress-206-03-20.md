## 2026-03-20

### AI-ready incident prompts

- Introduced a new `aegislog.ai` module that builds **LLM-ready prompts** for SSH incidents using structured incident data (IP, severity, events, auth stats, anomaly score) plus the existing human-written summary. The prompt guides an AI assistant to explain what is happening, assess brute-force behavior, and suggest next steps for a junior analyst. [web:183][web:186][web:188]
- Defined an `LLMIncidentPrompt` dataclass and a `build_incident_llm_prompt()` helper that returns a complete incident explanation prompt string without making any external API calls, creating a clean integration surface for future LLM clients. [web:183][web:186]
- Added an `explain_incident_with_llm()` placeholder that currently just echoes the prompt text, keeping logic for building prompts and invoking models clearly separated for future implementation. [web:179][web:188]

### CLI: inspect LLM prompts for incidents

- Extended the `incidents` CLI command with a `--print-llm-prompt` flag; when enabled, the CLI prints a fully formatted, ready-to-send LLM prompt between `llm_prompt_begin` and `llm_prompt_end` for each top SSH incident. This makes it easy to copy/paste directly into an LLM for manual testing. [web:183][web:186]
- Wired the AI helper into `cmd_incidents`: after printing the incident fields and rule-based summary, the command now optionally generates and displays the LLM prompt built from the same data, aligning with patterns used in recent work on LLM-based event log analysis and incident summarization. [web:179][web:183][web:188]
- Manually validated the end-to-end flow by running the `incidents` command with `--print-llm-prompt` against `data/loghub/SSH.log`, confirming that high-severity brute-force style SSH incidents produce clear summaries and detailed prompts suitable for AI-driven explanations. [web:185][web:187][web:192]

![alt text](image-1.png)

![alt text](image-2.png)

![alt text](image-3.png)