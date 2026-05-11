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