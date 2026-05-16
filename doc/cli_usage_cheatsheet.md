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

# 7) Normalize a generic syslog-style log into the common schema
python -m aegislog.cli normalize data/sample_syslog.log --input-format syslog

# 8) Group generic JSONL events into incidents
python -m aegislog.cli generic-incidents data/sample_generic.jsonl --top 5

# 9) Group generic syslog events into incidents
python -m aegislog.cli generic-incidents data/sample_syslog.log --input-format syslog --top 5

# 10) Explain a generic incident with AI-augmented analysis
python -m aegislog.cli generic-explain data/sample_generic.jsonl --index 0 --use-ai --format json --output generic_explain_ai.json

# 11) Group normalized events (generic/ssh/apache) into incidents
python -m aegislog.cli normalized-incidents data/sample_generic.jsonl --source-type generic
python -m aegislog.cli normalized-incidents data/loghub/SSH.log --source-type ssh
python -m aegislog.cli normalized-incidents data/loghub/Apache.log --source-type apache

# 12) Explain a normalized incident (generic/ssh/apache) with AI-augmented analysis
python -m aegislog.cli normalized-explain data/sample_generic.jsonl --source-type generic --first --use-ai
python -m aegislog.cli normalized-explain data/loghub/SSH.log --source-type ssh --index 0 --use-ai
python -m aegislog.cli normalized-explain data/loghub/Apache.log --source-type apache --index 0 --use-ai
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
- `normalize-ssh`
- `normalize-apache`
- `generic-incidents`
- `generic-explain`
- `normalized-incidents`
- `normalized-explain`
- `examples`

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
  - `summary` – short natural-language description,
  - `evidence` – bullet-style points referencing key metrics,
  - `hypothesis` – likely scenario,
  - `caveats` – limitations and uncertainties,
  - `next_steps` – concrete investigation / response actions,
  - `playbook_slug` and `playbook_notes` – which internal playbook was used.

AI backend via environment variables:

- `AEGISLOG_AI_BACKEND`:
  - `mock` (default),
  - `ollama`.
- `AEGISLOG_OLLAMA_MODEL`: model name (default: `llama3`).
- `AEGISLOG_OLLAMA_HOST`: base URL (default: `http://localhost:11434`).

If AI fails, you get a friendly `[AI analysis unavailable] ...` message and still get non-AI explain data.

Options mirror `incidents` plus:

- `--index`, `--first`
- `--use-llm`
- `--format`, `--output`

---

## ai-explain (SSH, structured AI-only)

Generate a **pure AI analysis JSON** for a single SSH incident.

```bash
python -m aegislog.cli ai-explain \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --first \
  --format json \
  --output ssh_ai_explain.json
```

Returns `{ incident_id, log_type, ip, severity, attack_pattern, ai_analysis, incident_evidence }`.

Options largely mirror `explain`.

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

Options include:

- `log_path`, `--log-type`, `--model-path`, `--model-type`, `--multi-score`,
- `--threshold-percentile`, `--top`,
- `--min-severity`, `--min-confidence`,
- `--format`, `--output`.

JSON reports include totals, severity/confidence/priority/attack_pattern counts, and top IPs/users.

---

## Generic logs: normalize, incidents, explain

These commands work on **generic logs** mapped into the normalized schema, using:

- `--input-format`:
  - `jsonl` (one JSON object per line),
  - `syslog` (RFC 3164-style syslog text),
- optional `--mapping` to map custom fields into the normalized event schema.

### normalize

Normalize a generic log into the common event schema:

```bash
# JSONL without mapping
python -m aegislog.cli normalize data/sample_generic.jsonl

# JSONL with field mapping
python -m aegislog.cli normalize data/sample_generic.jsonl --mapping mapping/example_auth_app.yaml

# Syslog (no mapping)
python -m aegislog.cli normalize data/sample_syslog.log --input-format syslog
```

Options:

- `path` (positional): Path to the input log file.
- `--input-format`: `jsonl` (default) or `syslog`.
- `--mapping`: Optional YAML/JSON mapping file.
- `--top`: Number of normalized events to preview (default: `5`).
- `--format`: `text` (default) or `json`.
- `--output`: Optional path to write JSON instead of stdout.

Text output prints:

- total event count,
- severity/category/action counts,
- first N normalized events,
- parse errors (up to 10).

JSON output includes:

- `path`, `input_format`, `mapping`, `summary`, `preview`, `parse_errors`.

### generic-incidents

Group normalized generic events into **generic incidents**:

```bash
# JSONL
python -m aegislog.cli generic-incidents \
  data/sample_generic.jsonl \
  --window-minutes 15 \
  --top 5

# JSONL with mapping
python -m aegislog.cli generic-incidents \
  data/sample_generic.jsonl \
  --mapping mapping/example_auth_app.yaml \
  --top 5

# Syslog
python -m aegislog.cli generic-incidents \
  data/sample_syslog.log \
  --input-format syslog \
  --top 5
```

Options:

- `path` (positional).
- `--input-format`: `jsonl` (default) or `syslog`.
- `--mapping`: Optional YAML/JSON mapping file.
- `--window-minutes`: Time window for grouping (default: `15`).
- `--top`: Number of incidents to show (default: `5`).
- `--format`: `text` (default) or `json`.
- `--output`: Optional path to write JSON instead of stdout.

Each generic incident includes:

- id, group_key, severity, confidence, priority, attack_pattern,
- event/error/warning counts,
- distinct users/hosts/src_ips,
- first_seen, last_seen, source_type,
- summary (title, description).

### generic-explain

Explain a single generic incident using the normalized schema and AI:

```bash
# Text explanation
python -m aegislog.cli generic-explain \
  data/sample_generic.jsonl \
  --index 0

# JSONL with mapping + AI
python -m aegislog.cli generic-explain \
  data/sample_generic.jsonl \
  --mapping mapping/example_auth_app.yaml \
  --index 0 \
  --use-ai \
  --format json \
  --output generic_explain_ai.json

# Syslog + AI
python -m aegislog.cli generic-explain \
  data/sample_syslog.log \
  --input-format syslog \
  --index 0 \
  --use-ai
```

Options:

- `path` (positional).
- `--input-format`: `jsonl` (default) or `syslog`.
- `--mapping`: Optional YAML/JSON mapping file.
- `--window-minutes`: Time window (default: `15`).
- `--index`: Zero-based incident index (default: `0`).
- `--first`: Explain the first incident.
- `--use-ai`: Enable structured AI analysis.
- `--format`: `text` (default) or `json`.
- `--output`: Optional path to write JSON instead of stdout.

JSON output includes:

- `path`, `input_format`, `mapping`,
- `window_minutes`, `selected_index`,
- `incident`, `incident_evidence`,
- `parse_errors`,
- optional `ai_analysis`.

---

## Normalized logs: normalized-incidents, normalized-explain

These commands operate on **normalized events** from:

- generic logs,
- SSH logs,
- Apache error logs.

### normalized-incidents

Group normalized events into incidents:

```bash
# Generic JSONL
python -m aegislog.cli normalized-incidents \
  data/sample_generic.jsonl \
  --source-type generic \
  --top 5

# Generic JSONL with mapping
python -m aegislog.cli normalized-incidents \
  data/sample_generic.jsonl \
  --source-type generic \
  --mapping mapping/example_auth_app.yaml \
  --top 5

# Generic syslog
python -m aegislog.cli normalized-incidents \
  data/sample_syslog.log \
  --source-type generic \
  --input-format syslog \
  --top 5

# SSH
python -m aegislog.cli normalized-incidents \
  data/loghub/SSH.log \
  --source-type ssh \
  --top 5

# Apache
python -m aegislog.cli normalized-incidents \
  data/loghub/Apache.log \
  --source-type apache \
  --top 5
```

Options:

- `path` (positional).
- `--source-type`: `generic`, `ssh`, `apache`.
- `--input-format`: `jsonl` or `syslog` (for `generic` only).
- `--mapping`: Optional mapping file (for `generic` only).
- `--window-minutes`: Time window (default: `15`).
- `--top`: Number of incidents to show (default: `5`).
- `--format`: `text` (default) or `json`.
- `--output`: Optional path to write JSON instead of stdout.

Output mirrors `generic-incidents`, but includes `source_type` and works across sources.

### normalized-explain

Explain a normalized incident from any source type:

```bash
# Generic JSONL + AI
python -m aegislog.cli normalized-explain \
  data/sample_generic.jsonl \
  --source-type generic \
  --first \
  --use-ai

# Generic syslog + mapping + AI
python -m aegislog.cli normalized-explain \
  data/sample_syslog.log \
  --source-type generic \
  --input-format syslog \
  --mapping mapping/example_auth_app.yaml \
  --first \
  --use-ai

# SSH
python -m aegislog.cli normalized-explain \
  data/loghub/SSH.log \
  --source-type ssh \
  --index 0 \
  --use-ai

# Apache
python -m aegislog.cli normalized-explain \
  data/loghub/Apache.log \
  --source-type apache \
  --index 0 \
  --use-ai
```

Options:

- `path` (positional).
- `--source-type`: `generic`, `ssh`, `apache`.
- `--input-format`: `jsonl` or `syslog` (for `generic` only).
- `--mapping`: Optional mapping file (for `generic` only).
- `--window-minutes`: Time window (default: `15`).
- `--index`: Zero-based incident index (default: `0`).
- `--first`: Explain the first incident.
- `--use-ai`: Enable structured AI analysis.
- `--format`: `text` (default) or `json`.
- `--output`: Optional path to write JSON instead of stdout.

JSON output is similar to `generic-explain`, but includes `source_type` and uses normalized evidence.

---

## Apache-specific CLI (`cli_apache`)

The dedicated Apache CLI focuses on suspicious Apache error sessions.

### Top suspicious Apache sessions (text)

```bash
python -m aegislog.cli_apache data/loghub/Apache.log --top 20
```

### Top suspicious Apache sessions (JSON)

```bash
python -m aegislog.cli_apache \
  data/loghub/Apache.log \
  --top 10 \
  --format json \
  --output apache_top.json
```

### Explain a single suspicious Apache session

```bash
python -m aegislog.cli_apache \
  data/loghub/Apache.log \
  --explain \
  --first
```

JSON evidence:

```bash
python -m aegislog.cli_apache \
  data/loghub/Apache.log \
  --explain \
  --first \
  --format json \
  --output apache_explain.json
```

### AI-augmented Apache explain

```bash
python -m aegislog.cli_apache \
  data/loghub/Apache.log \
  --ai-explain \
  --first \
  --format json \
  --output apache_explain_ai.json
```

### Apache report

```bash
# Text report
python -m aegislog.cli_apache \
  data/loghub/Apache.log \
  --report

# JSON report
python -m aegislog.cli_apache \
  data/loghub/Apache.log \
  --report \
  --format json \
  --output apache_report.json
```

### Apache filters

- `--min-score <float>`
- `--rare-hour-only`
- `--min-5xx-burst <int>`
- `--min-error-events <int>`

Core options:

- `log_path` (positional),
- `--log-type`, `--model-path`, `--model-type`,
- `--top`, `--explain`, `--ai-explain`, `--report`,
- `--index`, `--first`,
- filter options above,
- `--format`, `--output`.