***

# AegisLog CLI Usage Cheatsheet

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

***

## init

Initialize experiment database (currently a placeholder).

```bash
python -m aegislog.cli init
```

***

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

***

## analyze

Analyze logs, score sessions, and print top anomalous sessions.

```bash
python -m aegislog.cli analyze \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --model-path models/log_anomaly_iforest.joblib \
  --top 10
```

- `log_path` (positional): Path to log file to analyze.
- `--log-type`: Type of log file.
  - `apache_error` (default)
  - `ssh_auth`
- `--model-path`: Path to trained model.  
  Default: `models/log_anomaly_iforest.joblib`.
- `--top`: Number of most anomalous sessions to print.  
  Default: `5`.

***

## incidents

Group anomalous SSH sessions into simple IP-based incidents.

### Text output

```bash
python -m aegislog.cli incidents \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --model-path models/log_anomaly_iforest_ssh.joblib \
  --top 3 \
  --show-local-explanation
```

### JSON output (for tooling / integrations)

```bash
python -m aegislog.cli incidents \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --model-path models/log_anomaly_iforest_ssh.joblib \
  --top 3 \
  --format json
```

Options:

- `log_path` (positional): Path to SSH auth log file.
- `--log-type`: Type of log file.  
  Currently: `ssh_auth` (default).
- `--model-path`: Path to SSH anomaly model.  
  Default: `models/log_anomaly_iforest_ssh.joblib`.
- `--top`: Number of top incidents to print.  
  Default: `5`.
- `--show-local-explanation`: Print a simple, built-in AI-style explanation for each incident.
- `--print-llm-prompt`: Print a ready-to-send LLM prompt for each incident.
- `--format`: Output format.
  - `text` (default)
  - `json`

***

## explain

Explain a single SSH incident with AI-style output.

### Text output (no real LLM call, just prompt)

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
  --format json
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
- `--log-type`: Type of log file.  
  Currently: `ssh_auth` (default).
- `--model-path`: Path to SSH anomaly model.  
  Default: `models/log_anomaly_iforest_ssh.joblib`.
- `--index`: Zero-based index into the sorted list of incidents to explain.  
  Default: `0`.
- `--use-llm`: If set, call a real LLM to generate an explanation.
- `--format`: Output format.
  - `text` (default)
  - `json`

***
