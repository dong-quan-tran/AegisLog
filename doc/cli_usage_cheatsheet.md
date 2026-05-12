# AegisLog CLI Usage Cheatsheet


## Quick start

From the project root (with your virtualenv activated):

```bash
# 1) See the noisiest SSH sessions
python -m aegislog.cli analyze data/loghub/SSH.log --log-type ssh_auth --top 10

# 2) See the worst SSH incidents (medium+ severity)
python -m aegislog.cli incidents data/loghub/SSH.log --log-type ssh_auth --min-severity medium --top 5

# 3) Explain the highest-severity SSH incident with AI-augmented analysis (via Ollama or mock)
python -m aegislog.cli explain data/loghub/SSH.log --log-type ssh_auth --min-severity high --first --use-llm --format json --output explain_ai.json

# 4) See the top suspicious Apache error sessions via main CLI
python -m aegislog.cli analyze data/loghub/Apache.log --log-type apache_error --top 10

# 5) Use the dedicated Apache CLI to inspect sessions, explain one, see a report, or get AI analysis
python -m aegislog.cli_apache data/loghub/Apache.log -n 20
python -m aegislog.cli_apache data/loghub/Apache.log --explain --first
python -m aegislog.cli_apache data/loghub/Apache.log --report
python -m aegislog.cli_apache data/loghub/Apache.log --ai-explain --first --format json --output apache_explain_ai.json

# 6) Normalize a generic JSONL log into the common schema
python -m aegislog.cli normalize data/sample_generic.jsonl

# 7) Group generic JSONL events into incidents
python -m aegislog.cli generic-incidents data/sample_generic.jsonl --top 5

# 8) Explain a generic incident with AI-augmented analysis
python -m aegislog.cli generic-explain data/sample_generic.jsonl --index 0 --use-ai --format json --output generic_explain_ai.json
```


---

## Overview

Main entrypoint:

```bash
python -m aegislog.cli <subcommand> [options]
```

Available subcommands:

- `init`
- `train`
- `analyze`
- `incidents`
- `explain`
- `ai-explain`
- `report`
- `normalize`
- `generic-incidents`
- `generic-explain`

Additional Apache-specific CLI:

- `cli_apache` (run via `python -m aegislog.cli_apache`)


---

## init

Initialize experiment database (currently a placeholder).

```bash
python -m aegislog.cli init
```


---

## train

Train an anomaly detection model on logs and save it.

```bash
# SSH example
python -m aegislog.cli train \
  --logs-path data/loghub/SSH.log \
  --log-type ssh_auth \
  --model-path models/log_anomaly_iforest_ssh.joblib

# Apache error example
python -m aegislog.cli train \
  --logs-path data/loghub/Apache.log \
  --log-type apache_error \
  --model-path models/log_anomaly_iforest_apache.joblib
```

Key options:

- `--logs-path` (required): Path to training log file.
- `--log-type`: Feature extractor / pipeline to use:
  - `ssh_auth`
  - `apache_error`
- `--model-path` (optional): Where to save the trained model.  
  Default: `models/log_anomaly_iforest.joblib` (or a log-type-specific default).
- `--model-type`: `iforest` (default), `ocsvm`, `lof`.


---

## analyze

Analyze logs, score sessions, and print top anomalous sessions.

```bash
# SSH: analyze auth log
python -m aegislog.cli analyze \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --model-path models/log_anomaly_iforest_ssh.joblib \
  --top 10

# Apache: analyze error log
python -m aegislog.cli analyze \
  data/loghub/Apache.log \
  --log-type apache_error \
  --model-path models/log_anomaly_iforest_apache.joblib \
  --top 10
```

Common options:

- `log_path` (positional): Path to log file to analyze.
- `--log-type`:
  - `apache_error`
  - `ssh_auth`
- `--model-path`: Path to trained model.  
  Defaults depend on `--log-type` / `--profile`.
- `--model-type`: `iforest` (default), `ocsvm`, `lof`.
- `--multi-score`: Score with all models and include normalized/ensemble scores.
- `--top`: Number of most anomalous sessions to print.  
  Default: `5`.
- `--threshold-percentile`: Percentile threshold for marking sessions as anomalous.  
  Default: `99.0`.
- `--alerts-only`: Show only sessions at or above the anomaly threshold.
- `--format`: `text` (default) or `json`.
- `--output`: Optional path to write JSON instead of stdout.
- `--profile`: Shortcut:
  - `apache` → `--log-type apache_error` + Apache model default.
  - `ssh` → `--log-type ssh_auth` + SSH model default.


---

## incidents

Group anomalous SSH sessions into simple IP-based incidents.

### Text output

```bash
python -m aegislog.cli incidents \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --model-path models/log_anomaly_iforest_ssh.joblib \
  --top 3 \
  --show-local-explanation \
  --show-timeline
```

### JSON output (for tooling / integrations)

```bash
python -m aegislog.cli incidents \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --model-path models/log_anomaly_iforest_ssh.joblib \
  --top 3 \
  --format json \
  --output incidents.json
```

Key options:

- `log_path` (positional): Path to SSH auth log file.
- `--log-type`: Currently `ssh_auth` only (default).
- `--model-path`: Path to SSH anomaly model.  
  Default: `models/log_anomaly_iforest_ssh.joblib`.
- `--model-type`: `iforest` (default), `ocsvm`, `lof`.
- `--top`: Number of top incidents to print.  
  Default: `5`.
- `--threshold-percentile`: Percentile threshold used before grouping incidents.  
  Default: `99.0`.
- `--alerts-only`: Group incidents only from threshold-flagged anomalous sessions.
- `--show-local-explanation`: Print a simple, built-in AI-style explanation per incident.
- `--print-llm-prompt`: Print a ready-to-send LLM explanation prompt per incident.
- `--show-timeline`: Print a per-incident session timeline ordered by time.
- `--min-severity`: Filter incidents at or above this severity:
  - `low`, `medium`, `high`.
- `--min-confidence`: Filter incidents at or above this confidence:
  - `low`, `medium`, `high`.
- `--sort-by`: Sort incidents before applying `--top`:
  - `severity`, `avg_score`, `auth_fail_ratio`, `total_events`.
- `--format`: `text` (default) or `json`.
- `--output`: Optional path to write JSON instead of stdout.

JSON incidents include:

- incident fields (id, ip, severity, severity_reason, confidence, confidence_reason, priority, priority_score, priority_reason, attack_pattern, attack_pattern_reason, session_ids, totals, first/last seen, primary_user, targeted_users)
- summary (title, description)
- local_explanation
- llm_prompt (prompt text only)


---

## explain (SSH incidents)

Explain a single SSH incident with AI-style output and optional structured AI analysis.

### Explain the highest-severity incident

```bash
python -m aegislog.cli explain \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --min-severity high \
  --first
```

### Explain a specific incident by index

```bash
python -m aegislog.cli explain \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --model-path models/log_anomaly_iforest_ssh.joblib \
  --index 0
```

### JSON bundle (incident + summary + explanation + prompt)

```bash
python -m aegislog.cli explain \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --model-path models/log_anomaly_iforest_ssh.joblib \
  --index 0 \
  --format json \
  --output explain.json
```

### AI-augmented explain (structured analysis via Ollama or mock)

```bash
# Write AI-augmented explain JSON to a file
python -m aegislog.cli explain \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --first \
  --use-llm \
  --format json \
  --output explain_ai.json
```

This produces a JSON object that includes:

- all the usual explain fields (`incident`, `summary`, `local_explanation`, `llm_prompt`, `incident_evidence`),
- a new `ai_analysis` object with:
  - `summary` – short natural-language description of the incident,
  - `evidence` – bullet-style points referencing key metrics,
  - `hypothesis` – likely scenario (e.g., brute force, password spray, possible compromise),
  - `caveats` – limitations and uncertainties,
  - `next_steps` – concrete investigation / response actions,
  - `playbook_slug` and `playbook_notes` – which internal playbook was used to suggest next steps.

The AI backend is controlled by environment variables:

- `AEGISLOG_AI_BACKEND`:
  - `mock` (default): deterministic, provider-free backend.
  - `ollama`: use a local Ollama model (e.g., `llama3`).
- `AEGISLOG_OLLAMA_MODEL`: model name for Ollama (default: `llama3`).
- `AEGISLOG_OLLAMA_HOST`: Ollama base URL (default: `http://localhost:11434`).

If Ollama is enabled and reachable, the `ai_analysis` block is generated by the local model. If the AI backend fails (network error, bad config), the CLI prints a friendly `[AI analysis unavailable] ...` message and still returns the non-AI explain data without crashing.

Options:

- `log_path` (positional): Path to SSH auth log file.
- `--log-type`: Currently `ssh_auth` only (default).
- `--model-path`: Path to SSH anomaly model.  
  Default: `models/log_anomaly_iforest_ssh.joblib`.
- `--index`: Zero-based index into the incident list after filtering.  
  Default: `0`.
- `--min-severity`: Only consider incidents at or above this severity when selecting:
  - `low`, `medium`, `high`.
- `--min-confidence`: Only consider incidents at or above this confidence when selecting:
  - `low`, `medium`, `high`.
- `--first`: Explain the first incident after applying severity/confidence/pattern filters.
- `--use-llm`: Enable structured AI analysis via the configured backend.
- `--format`: `text` (default) or `json`.
- `--output`: Optional path to write JSON instead of stdout.
- `--model-type`: `iforest` (default), `ocsvm`, `lof`.


---

## ai-explain (SSH, structured AI-only)

Generate a **pure AI analysis JSON** for a single SSH incident (no prompt/local explanation wrapper).

```bash
python -m aegislog.cli ai-explain \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --first \
  --format json \
  --output ssh_ai_explain.json
```

This:

- selects an SSH incident using the same filters/sorting as `explain`,
- builds `IncidentEvidence`,
- calls the configured AI backend,
- returns `{ incident_id, log_type, ip, severity, attack_pattern, ai_analysis, incident_evidence }` as JSON.

Options mirror `explain` (index, first, severity/confidence filters, model-path, etc.), with `--format` and `--output` required for JSON output.


---

## report

Summarize anomalous sessions and grouped incidents with aggregate metrics (SSH).

### Text output

```bash
python -m aegislog.cli report \
  data/loghub/SSH.log \
  --log-type ssh_auth
```

### JSON output

```bash
python -m aegislog.cli report \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --min-severity medium \
  --format json \
  --output report.json
```

Options:

- `log_path` (positional): Path to SSH auth log file.
- `--log-type`: Currently `ssh_auth` only (default).
- `--model-path`: Path to anomaly model (if omitted, uses defaults).
- `--model-type`: `iforest` (default), `ocsvm`, `lof`.
- `--multi-score`: Score with all models and include normalized/ensemble scores.
- `--threshold-percentile`: Percentile threshold for treating sessions as anomalous before reporting.  
  Default: `99.0`.
- `--top`: Number of top IPs/users to include in the report.  
  Default: `5`.
- `--min-severity`: Only include incidents at or above this severity:
  - `low`, `medium`, `high`.
- `--min-confidence`: Only include incidents at or above this confidence:
  - `low`, `medium`, `high`.
- `--format`: `text` (default) or `json`.
- `--output`: Optional path to write JSON instead of stdout.

JSON reports include:

- `total_sessions`
- `anomalous_sessions`
- `anomalous_session_percent`
- `total_incidents`
- `severity_counts`
- `confidence_counts`
- `priority_counts`
- `attack_pattern_counts`
- `top_incident_ips`
- `top_targeted_users`


---

## Generic logs: normalize, incidents, explain

These commands work on **generic JSONL logs** mapped into the normalized schema.

### normalize

Normalize a generic JSONL log into the common event schema:

```bash
python -m aegislog.cli normalize data/sample_generic.jsonl
```

Options:

- `path` (positional): Path to the input log file.
- `--input-format`: Currently `jsonl` only.
- `--top`: Number of normalized events to preview (default: `5`).
- `--format`: `text` (default) or `json`.
- `--output`: Optional path to write JSON instead of stdout.

Text output prints:

- total event count,
- severity/category/action counts,
- first N normalized events,
- parse errors (up to 10), if any.

JSON output includes:

- `path`, `input_format`, `summary`, `preview`, `parse_errors`.


### generic-incidents

Group normalized generic events into **generic incidents** using the normalized schema:

```bash
python -m aegislog.cli generic-incidents \
  data/sample_generic.jsonl \
  --window-minutes 15 \
  --top 5
```

Options:

- `path` (positional): Path to the input log file.
- `--input-format`: `jsonl` (default).
- `--window-minutes`: Time window used for grouping (default: `15`).
- `--top`: Number of incidents to show (default: `5`).
- `--format`: `text` (default) or `json`.
- `--output`: Optional path to write JSON instead of stdout.

Each generic incident includes:

- `incident_id`
- `group_key`
- `severity` (`low`, `medium`, `high`)
- `confidence` (`low`, `medium`, `high`)
- `priority` (`low`, `medium`, `high`, `critical`)
- `attack_pattern` (e.g. `error_spike`, `warning_burst`, `auth_fail_burst`, `unknown_anomalous_behavior`)
- `event_count`, `error_count`, `warning_count`
- `distinct_users`, `distinct_hosts`, `distinct_src_ips`
- `first_seen`, `last_seen`
- `source_type`
- `summary` (title, description)


### generic-explain

Explain a single generic incident using the normalized schema and the same AI backend as SSH/Apache:

```bash
# Text explanation of one generic incident
python -m aegislog.cli generic-explain \
  data/sample_generic.jsonl \
  --index 0

# AI-augmented JSON explanation
python -m aegislog.cli generic-explain \
  data/sample_generic.jsonl \
  --index 0 \
  --use-ai \
  --format json \
  --output generic_explain_ai.json
```

Behavior:

- loads and normalizes generic JSONL events,
- groups them into incidents using the same generic rules as `generic-incidents`,
- selects one incident by `--index` or `--first`,
- builds generic `IncidentEvidence` from normalized data (counts, distinct entities, sample events),
- optionally calls the configured AI backend for structured analysis.

JSON output includes:

- `path`, `input_format`, `window_minutes`, `selected_index`,
- `incident` (generic incident fields as above),
- `incident_evidence` (normalized evidence for the selected incident),
- `parse_errors`,
- optional `ai_analysis` with the same schema as SSH/Apache (`summary`, `evidence`, `hypothesis`, `caveats`, `next_steps`, `playbook_slug`, `playbook_notes`).

Options:

- `path` (positional): Path to the input log file.
- `--input-format`: `jsonl` (default).
- `--window-minutes`: Time window used for grouping (default: `15`).
- `--index`: Zero-based index into the grouped generic incidents (default: `0`).
- `--first`: Explain the first generic incident.
- `--use-ai`: Enable structured AI analysis via the configured backend.
- `--format`: `text` (default) or `json`.
- `--output`: Optional path to write JSON instead of stdout.


---

## Apache-specific CLI (`cli_apache`)

The dedicated Apache CLI focuses on suspicious Apache error sessions, with list, explain, report, JSON output, and filters.

### Top suspicious Apache sessions (text)

```bash
python -m aegislog.cli_apache data/loghub/Apache.log --top 20
```

This will:

- Parse the Apache error log (`Apache.log`).
- Build sessions and Apache-focused features (error vs notice ratio, bursts, rare templates, rare hour, etc.).
- Score sessions using the resolved Apache model.
- Print the top N suspicious sessions with:
  - session id (derived from the session timeframe),
  - anomaly score,
  - error ratio,
  - 5xx burst size,
  - human-readable notes (e.g. “errors dominate over notices”, “many rare error templates”, “activity during unusual hours”).

### Top suspicious Apache sessions (JSON)

```bash
python -m aegislog.cli_apache \
  data/loghub/Apache.log \
  --top 10 \
  --format json \
  --output apache_top.json
```

Produces a JSON array of session summaries, each with fields like `session_id`, `score`, `error_ratio`, and `apache_notes`.

### Explain a single suspicious Apache session

```bash
# Explain the first suspicious session after sorting
python -m aegislog.cli_apache \
  data/loghub/Apache.log \
  --explain \
  --first
```

- Prints a short summary (score, error ratio, 5xx burst, notes).
- Builds Apache `IncidentEvidence` and prints key highlights and metrics (e.g. status_5xx, error_events, rare templates, rare path ratio).

JSON evidence:

```bash
python -m aegislog.cli_apache \
  data/loghub/Apache.log \
  --explain \
  --first \
  --format json \
  --output apache_explain.json
```

Produces a single evidence object with:

- `incident_id` (e.g. `apache:<session-id>`),
- `log_type` (`apache_error`),
- `model_type`,
- `highlights`,
- `sessions` (one session with Apache-focused evidence),
- `extra` (raw metrics used to build the explanation).

### AI-augmented Apache explain (structured analysis)

```bash
# Write AI-augmented Apache explain JSON to a file
python -m aegislog.cli_apache \
  data/loghub/Apache.log \
  --ai-explain \
  --first \
  --format json \
  --output apache_explain_ai.json
```

This uses the same Apache anomaly model and evidence as `--explain`, but adds an AI-generated `ai_analysis` object that includes:

- a short natural-language summary,
- evidence-style bullet points tied to Apache metrics (bursts, rare templates, unusual hours),
- a hypothesis about what the pattern might indicate,
- caveats and recommended next steps.

If AI analysis fails (for example, due to an upstream error), the command will:

- print a clear `AI analysis failed: ...` (or similar) message, and
- exit with a non-zero status code,

while leaving the regular `--explain` and `--report` behavior unchanged.

### Apache report (aggregate metrics)

```bash
# Text report
python -m aegislog.cli_apache \
  data/loghub/Apache.log \
  --report
```

```bash
# JSON report
python -m aegislog.cli_apache \
  data/loghub/Apache.log \
  --report \
  --format json \
  --output apache_report.json
```

The report summarizes the top suspicious sessions after sorting and (optionally) filtering, including:

- total sessions considered,
- rare-hour sessions,
- sessions with 5xx bursts,
- sessions with error bursts,
- sessions with rare error templates,
- sessions with high severity ratios,
- sessions where errors dominate notices,
- total error events,
- top session IDs by score.

### Apache filters

You can narrow which Apache sessions are listed, explained, or reported:

- `--min-score <float>`: Only include sessions at or above this anomaly/ensemble score.
- `--rare-hour-only`: Only include sessions that occurred during unusual hours.
- `--min-5xx-burst <int>`: Only include sessions with at least this many 5xx events in a one-minute burst.
- `--min-error-events <int>`: Only include sessions with at least this many Apache error events.

Examples:

```bash
# Report only on sessions during rare hours
python -m aegislog.cli_apache \
  data/loghub/Apache.log \
  --report \
  --rare-hour-only

# JSON top sessions with at least 100 error events
python -m aegislog.cli_apache \
  data/loghub/Apache.log \
  --top 5 \
  --min-error-events 100 \
  --format json \
  --output apache_filtered_top.json

# Try to explain a session with an extreme 5xx burst (may yield no sessions)
python -m aegislog.cli_apache \
  data/loghub/Apache.log \
  --explain \
  --first \
  --min-5xx-burst 999999
```

Core Apache options:

- `log_path` (positional): Path to Apache error log file.
- `--log-type`: `apache_error` (default).
- `--model-path`: Path to Apache anomaly model (or default via `resolve_model_path`).
- `--model-type`: `iforest` (default), `ocsvm`, `lof`.
- `--top`: Number of top sessions to show or consider.  
  Default: `20`.
- `--explain`: Explain a single suspicious Apache session.
- `--report`: Show an aggregate Apache report.
- `--index`: Zero-based index into the filtered/sorted list when using `--explain`.
- `--first`: Explain the first session after filtering and sorting.
- `--min-score`: Minimum score threshold.
- `--rare-hour-only`: Only sessions with `apache_rare_hour > 0`.
- `--min-5xx-burst`: Minimum `apache_5xx_burst_max_per_minute`.
- `--min-error-events`: Minimum `error_events`.
- `--format`: `text` (default) or `json`.
- `--output`: Optional path to write JSON instead of stdout.