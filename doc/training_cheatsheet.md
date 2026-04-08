# Aegislog Training Cheatsheet

This cheatsheet explains how to train anomaly detection models for Aegislog and how those models connect to the `analyze` and `incidents` commands.

---

## 1. Command overview

Aegislog exposes training via the CLI:

```bash
aegislog train --logs-path <PATH> --model-path <OUTPUT>
```

This is wired to `cmd_train`, which internally calls `aegislog.ml.train.main(...)`.

- `--logs-path`  
  Path to a log file used as training data.
- `--model-path` (optional)  
  Where to save the trained model (defaults to `models/log_anomaly_iforest.joblib`).

The saved model can then be used by `analyze` and `incidents` via their `--model-path` options.

---

## 2. Basic training workflow

### Step 1 – Prepare logs

- Use a representative log file for the environment you care about.
- For SSH workflows in this project, that’s typically an `ssh_auth`-style log (e.g. LogHub SSH).

Example:

```bash
ls data/loghub
SSH.log
```

### Step 2 – Train an Isolation Forest model

Train on an SSH log and save a model:

```bash
aegislog train \
  --logs-path data/loghub/SSH.log \
  --model-path models/log_anomaly_iforest_ssh.joblib
```

This will:

- read sessions from `data/loghub/SSH.log`,
- fit an anomaly model,
- write the model to `models/log_anomaly_iforest_ssh.joblib`.

### Step 3 – Use the model with `analyze`

```bash
aegislog analyze \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --model-path models/log_anomaly_iforest_ssh.joblib \
  --top 10
```

Or with percentile thresholding:

```bash
aegislog analyze \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --model-path models/log_anomaly_iforest_ssh.joblib \
  --threshold-percentile 99 \
  --alerts-only \
  --top 10
```

### Step 4 – Use the model with `incidents`

```bash
aegislog incidents \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --model-path models/log_anomaly_iforest_ssh.joblib \
  --threshold-percentile 99 \
  --alerts-only \
  --top 5
```

---

## 3. How training relates to `model-type` and defaults

The CLI currently supports a `--model-type` flag on `analyze`, `incidents`, and `explain`:

```bash
--model-type {iforest, ocsvm, lof}
```

Internally, helper functions like `resolve_model_path` pick default model paths based on:

- `log_type` (e.g. `ssh_auth` vs `apache_error`)
- `model_type` (e.g. `iforest`, `ocsvm`, `lof`)

Examples of defaults (may vary slightly with code):

- `iforest` + `ssh_auth` → `models/log_anomaly_iforest_ssh.joblib`
- `iforest` + `apache_error` → `models/log_anomaly_iforest_apache.joblib`

If you train your own model and pass `--model-path`, that explicit path takes precedence over any defaults.

---

## 4. Common usage patterns

### Train once, then reuse

For a given environment:

```bash
# 1) Train from representative logs
aegislog train \
  --logs-path /var/log/auth.log \
  --model-path models/log_anomaly_iforest_prod_ssh.joblib

# 2) Analyze recent logs with your trained model
aegislog analyze \
  /var/log/auth.log \
  --log-type ssh_auth \
  --model-path models/log_anomaly_iforest_prod_ssh.joblib \
  --threshold-percentile 99 \
  --alerts-only

# 3) Group into incidents using the same model
aegislog incidents \
  /var/log/auth.log \
  --log-type ssh_auth \
  --model-path models/log_anomaly_iforest_prod_ssh.joblib \
  --threshold-percentile 99 \
  --alerts-only
```

### Using profiles with defaults

For quick experiments, you can rely on profiles or default paths:

```bash
# Analyze using the built-in SSH profile and default model path
aegislog analyze \
  data/loghub/SSH.log \
  --profile ssh \
  --top 10
```

Behind the scenes, the `ssh` profile sets:

- `log_type = ssh_auth`
- `model_path = models/log_anomaly_iforest_ssh.joblib` (if not explicitly provided)

### JSON output for automation

Combine training with machine-readable output for downstream tooling:

```bash
# Analyze with a trained model and output JSON
aegislog analyze \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --model-path models/log_anomaly_iforest_ssh.joblib \
  --threshold-percentile 99 \
  --alerts-only \
  --format json \
  --output analyze_ssh.json

# Incidents as JSON
aegislog incidents \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --model-path models/log_anomaly_iforest_ssh.joblib \
  --threshold-percentile 99 \
  --alerts-only \
  --format json \
  --output incidents_ssh.json
```

---

## 5. Quick reference

- Train:
  - `aegislog train --logs-path <LOGFILE> --model-path <MODELFILE>`
- Analyze with custom model:
  - `aegislog analyze <LOGFILE> --log-type ssh_auth --model-path <MODELFILE>`
- Analyze with thresholding:
  - `--threshold-percentile 99 --alerts-only`
- Group incidents with the same model:
  - `aegislog incidents <LOGFILE> --log-type ssh_auth --model-path <MODELFILE>`
