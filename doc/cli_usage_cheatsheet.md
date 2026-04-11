# AegisLog CLI Usage Cheatsheet

## Quick start

From the project root (with your virtualenv activated):

```bash
# 1) See the noisiest sessions
python -m aegislog.cli analyze data/loghub/SSH.log --log-type ssh_auth --top 10

# 2) See the worst SSH incidents (medium+ severity)
python -m aegislog.cli incidents data/loghub/SSH.log --log-type ssh_auth --min-severity medium --top 5

# 3) Explain the highest-severity SSH incident
python -m aegislog.cli explain data/loghub/SSH.log --log-type ssh_auth --min-severity high --first
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
python -m aegislog.cli train \
  --logs-path data/loghub/SSH.log \
  --model-path models/log_anomaly_iforest.joblib
```

- `--logs-path` (required): Path to training log file.  
- `--model-path` (optional): Where to save the trained model.  
  Default: `models/log_anomaly_iforest.joblib`.

---

## analyze

Analyze logs, score sessions, and print top anomalous sessions.

```bash
python -m aegislog.cli analyze \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --model-path models/log_anomaly_iforest_ssh.joblib \
  --top 10
```

Common options:

- `log_path` (positional): Path to log file to analyze.
- `--log-type`:
  - `apache_error` (default)
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
- `--format`: `text` (default) or `json`.
- `--output`: Optional path to write JSON instead of stdout.

JSON incidents include:

- incident fields (id, ip, severity, severity_reason, confidence, confidence_reason, session_ids, totals, first/last seen, primary_user, targeted_users)
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

Summarize anomalous sessions and grouped incidents with aggregate metrics.

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
- `top_incident_ips`
- `top_targeted_users`