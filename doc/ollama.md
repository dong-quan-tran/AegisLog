# AegisLog Ollama Setup

This guide explains how to enable the local Ollama backend for AegisLog so AI explain features use a real local model instead of the mock backend.

## What this gives you

With Ollama enabled, AegisLog can send structured SSH incident evidence or Apache session evidence to a local LLM running on your machine. Ollama exposes a local API on `http://localhost:11434` and supports running chat models such as Llama locally without per-token API costs.[1][2]

## Requirements

- Ollama installed on your machine.[3]
- A pulled local model such as `llama3` or `llama3.2`.[4][5]
- AegisLog updated so `aegislog/ai/client.py` supports the `ollama` backend.[6][7]

## Install Ollama

On Windows, the easiest setup is to download and run `OllamaSetup.exe`; the installer adds the CLI and runs the local service in the background.[3]

After install, verify Ollama is available:

```powershell
ollama --version
```

If needed, you can manually start the server with:

```powershell
ollama serve
```

Ollama serves its local API at `http://localhost:11434`.[3][8]

## Pull a model

A simple default choice is `llama3`:

```powershell
ollama pull llama3
```

You can also use smaller models like `llama3.2` if you want a lighter local setup.[4][5]

To verify the model works:

```powershell
ollama run llama3
```

That opens an interactive local chat session.[4]

## Enable Ollama in AegisLog

Set these environment variables in PowerShell before running AegisLog:

```powershell
$env:AEGISLOG_AI_BACKEND="ollama"
$env:AEGISLOG_OLLAMA_MODEL="llama3"
```

Optional override for a non-default Ollama host:

```powershell
$env:AEGISLOG_OLLAMA_HOST="http://localhost:11434"
```

## Example commands

### SSH AI explain

```powershell
python -m aegislog.cli explain data/loghub/SSH.log --log-type ssh_auth --first --use-llm --format json --output explain_ai.json
```

### Apache AI explain

```powershell
python -m aegislog.cli_apache data/loghub/Apache.log --ai-explain --first --format json --output apache_explain_ai.json
```

With the Ollama backend enabled, these commands use the local Ollama chat API instead of the mock backend.[6][7]

## Troubleshooting

- `AI analysis failed: Failed to reach Ollama...` means the Ollama service is not running or the host/port is wrong.
- `AI analysis failed: Ollama returned HTTP ...` usually means the selected model has not been pulled yet or the request format failed.
- If generation is slow, try a smaller model such as `llama3.2` instead of a larger one.[5][9]

Useful checks:

```powershell
curl http://localhost:11434
ollama list
```

`ollama list` shows which local models are available, and the local API should respond on port 11434 when the service is running.[9][3]

## Suggested commit message

```text
feat(ai): add Ollama backend for local incident analysis
```

# OLLAMA_INTEGRATION_PLAN.md

# AegisLog Ollama Integration Plan

## Goal

Add a real local LLM backend to AegisLog using Ollama so SSH and Apache AI explain flows use an actual model instead of the current mock backend, while keeping the app free to use and safe for local log analysis.

---

## Phase 1 — Local setup

- [ ] Install Ollama on the development machine.
- [ ] Verify the CLI works with `ollama --version`.
- [ ] Start the local service and confirm the API is reachable on `http://localhost:11434`.
- [ ] Pull an initial model:
  - [ ] Try `llama3` first.
  - [ ] If performance is too slow, try a smaller model such as `llama3.2`.
- [ ] Confirm the model works manually with:
  - [ ] `ollama run llama3`

### Done when
- [ ] Ollama is installed.
- [ ] A local model is pulled.
- [ ] Manual chat works.

---

## Phase 2 — Backend wiring

- [ ] Replace the current mock-only AI path with backend selection in `aegislog/ai/client.py`.
- [ ] Keep `mock` as a fallback backend.
- [ ] Add `ollama` as a real backend.
- [ ] Support environment variables:
  - [ ] `AEGISLOG_AI_BACKEND`
  - [ ] `AEGISLOG_OLLAMA_MODEL`
  - [ ] `AEGISLOG_OLLAMA_HOST`
- [ ] Keep the same returned schema:
  - [ ] `summary`
  - [ ] `evidence`
  - [ ] `hypothesis`
  - [ ] `caveats`
  - [ ] `next_steps`
  - [ ] `playbook_slug`
  - [ ] `playbook_notes`
- [ ] Keep `validate_ai_analysis(...)` as the final guardrail.

### Done when
- [ ] SSH and Apache AI paths can call Ollama without changing CLI command shapes.
- [ ] Invalid model output still raises `LLMError`.

---

## Phase 3 — Prompt quality

- [ ] Review `aegislog/ai/prompts.py` so prompts are optimized for local models.
- [ ] Keep prompts short, structured, and explicit.
- [ ] Instruct the model to return JSON only.
- [ ] Include only the fields needed for analysis.
- [ ] Avoid dumping unnecessary raw log text into prompts.
- [ ] Prefer structured evidence over free-form logs.

### Done when
- [ ] The model returns useful JSON consistently.
- [ ] Prompt size stays small enough for local inference.

---

## Phase 4 — Structured outputs reliability

- [ ] Start with Ollama JSON mode / structured output mode.
- [ ] Keep schema validation in Python even if Ollama is asked for JSON.
- [ ] Add graceful handling for:
  - [ ] empty output
  - [ ] partial JSON
  - [ ] invalid field types
  - [ ] timeout
  - [ ] connection failure
- [ ] Keep CLI behavior clean:
  - [ ] show `AI analysis failed: ...`
  - [ ] return non-zero exit code
- [ ] Do not let malformed model output crash the whole CLI unexpectedly.

### Done when
- [ ] Bad responses fail safely.
- [ ] Good responses parse and validate reliably.

---

## Phase 5 — SSH rollout first

- [ ] Test Ollama-backed SSH explain first.
- [ ] Run:
  - [ ] normal `explain`
  - [ ] `explain --use-llm`
  - [ ] JSON output mode
- [ ] Compare mock vs Ollama outputs for usefulness.
- [ ] Tune prompt wording if SSH hypotheses or next steps are weak.
- [ ] Check that existing SSH tests still pass.

### Done when
- [ ] SSH AI explain works end-to-end with Ollama.
- [ ] Output quality is acceptable for demo and local use.

---

## Phase 6 — Apache rollout second

- [ ] Test Apache `--ai-explain` with Ollama.
- [ ] Verify Apache evidence is prompt-friendly.
- [ ] Check whether Apache prompts need different wording from SSH prompts.
- [ ] Confirm existing Apache AI failure handling still works.
- [ ] Verify JSON output remains stable.

### Done when
- [ ] Apache AI explain works end-to-end with Ollama.
- [ ] Apache failure handling still behaves correctly.

---

## Phase 7 — Documentation

- [ ] Add an Ollama setup guide to `doc/`.
- [ ] Update `README.md` with:
  - [ ] what Ollama is
  - [ ] how to install it
  - [ ] how to enable the backend
  - [ ] example SSH command
  - [ ] example Apache command
- [ ] Update cheatsheets to mention Ollama backend selection.
- [ ] Clarify that AI explain uses local Ollama when enabled, otherwise mock mode.

### Done when
- [ ] A new user can set up local AI without guessing.

---

## Phase 8 — Safety and long-term security

- [ ] Keep Ollama bound to local-only usage unless there is a strong reason otherwise.
- [ ] Do not expose the Ollama port publicly.
- [ ] Keep Ollama updated over time because local LLM frameworks can still have vulnerabilities.
- [ ] Continue validating all model output before use.
- [ ] Avoid sending secrets or unnecessary raw logs when structured evidence is enough.
- [ ] Consider redacting especially sensitive fields later:
  - [ ] usernames
  - [ ] internal IPs
  - [ ] hostnames
  - [ ] tokens/credentials if ever present
- [ ] Log backend choice and model name for debugging.
- [ ] Optionally add prompt/response audit metadata later without storing sensitive raw content.

### Done when
- [ ] Local AI remains private-by-default.
- [ ] The system is resilient even if the model behaves badly.

---

## Phase 9 — Performance and UX

- [ ] Measure response time on your machine.
- [ ] If too slow, test a smaller model.
- [ ] Keep prompts compact so local inference stays responsive.
- [ ] Consider adding a timeout setting later.
- [ ] Decide whether AI output should be optional by default or auto-enabled when Ollama is detected.

### Done when
- [ ] The AI flow feels usable in normal CLI work.

---

## Phase 10 — Future features

- [ ] Add a conversational CLI later, for example:
  - [ ] `python -m aegislog.cli chat ...`
- [ ] Let users ask questions like:
  - [ ] “Why is this incident high severity?”
  - [ ] “Summarize suspicious sessions from rare hours.”
  - [ ] “What should I investigate first?”
- [ ] Reuse the same Ollama backend and evidence-building code.
- [ ] Consider retrieval over:
  - [ ] scored sessions
  - [ ] incidents
  - [ ] reports
  - [ ] timelines

### Done when
- [ ] AegisLog supports both explain-style AI and chat-style AI.

---

## Long-term judgment

### Is Ollama a good long-term choice?
- [ ] Yes, for local/private, zero-token-cost AI features.
- [ ] Yes, especially for sensitive logs where cloud upload is undesirable.
- [ ] Yes, as the default free backend.

### What are the tradeoffs?
- [ ] Output quality may be less consistent than top paid cloud models.
- [ ] Structured JSON can still fail sometimes, so validation stays mandatory.
- [ ] Performance depends on local hardware.
- [ ] You must maintain local security and updates yourself.

### Safe long-term if we do this?
- [ ] Yes, if we keep it local-only, validate outputs, avoid public exposure, and keep Ollama updated.