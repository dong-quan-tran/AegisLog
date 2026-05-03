# AegisLog CLI Usage Cheatsheet

## Quick start

From the project root (with your virtualenv activated):

```bash
# 1) See the noisiest SSH sessions
python -m aegislog.cli analyze data/loghub/SSH.log --log-type ssh_auth --top 10

# 2) See the worst SSH incidents (medium+ severity)
python -m aegislog.cli incidents data/loghub/SSH.log --log-type ssh_auth --min-severity medium --top 5

# 3) Explain the highest-severity SSH incident
python -m aegislog.cli explain data/loghub/SSH.log --log-type ssh_auth --min-severity high --first

# 4) See the top suspicious Apache error sessions (using Apache model defaults)
python -m aegislog.cli analyze data/loghub/Apache.log --log-type apache_error --top 10

# 5) Use the dedicated Apache CLI to inspect suspicious sessions
python -m aegislog.cli_apache data/loghub/Apache.log -n 20
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
- `report`

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

## explain

Explain a single SSH incident with AI-style output.

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

### Call a real LLM (requires OPENAI_API_KEY)

```bash
python -m aegislog.cli explain \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --model-path models/log_anomaly_iforest_ssh.joblib \
  --index 0 \
  --use-llm
```

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
- `--first`: Explain the first incident after applying severity/confidence filters.
- `--use-llm`: Call a real LLM for the explanation (otherwise only prints the constructed prompt).
- `--format`: `text` (default) or `json`.
- `--output`: Optional path to write JSON instead of stdout.
- `--model-type`: `iforest` (default), `ocsvm`, `lof`.

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

## Apache-specific CLI (`cli_apache`)

For quick inspection of suspicious Apache error sessions, you can use the dedicated Apache CLI, which runs directly on `.log` files.

### Basic usage

```bash
python -m aegislog.cli_apache data/loghub/Apache.log -n 20
```

This will:

- Parse the Apache error log (`Apache.log`).
- Build sessions and Apache-focused features (error vs notice ratio, bursts, rare templates, rare hour, etc.).
- Score sessions using the resolved Apache model (or defaults).
- Print the top 20 suspicious sessions with:

  - session id (derived from session timeframe),
  - anomaly score,
  - error ratio,
  - 5xx burst size,
  - human-readable notes (e.g. “errors dominate over notices”, “many rare error templates”, “activity during unusual hours”).

### Options

- `log_path` (positional): Path to Apache error log file.
- `--log-type`: Currently `apache_error` only (default).
- `--model-path`: Path to Apache anomaly model.  
  If omitted, uses the Apache default for the selected `--model-type`.
- `--model-type`: `iforest` (default), `ocsvm`, `lof`.
- `-n`, `--top`: Number of top suspicious sessions to show.  
  Default: `20`.

This is the fastest way to get a human-readable view of suspicious Apache error behavior without going through the full `analyze`/`incidents` flow.