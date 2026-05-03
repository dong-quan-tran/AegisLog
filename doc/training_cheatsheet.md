# Aegislog Training Cheatsheet

This cheatsheet explains how to train anomaly detection models for Aegislog and how those models connect to the `analyze`, `incidents`, and Apache CLI commands.

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
- `--log-type` (optional)  
  Log type for feature extraction (e.g. `ssh_auth`, `apache_error`).

The saved model can then be used by:

- `analyze` and `incidents` via their `--model-path` options.
- The Apache-specific CLI (`python -m aegislog.cli_apache`) via its `--model-path` option.

---

## 2. Basic training workflow

### Step 1 – Prepare logs

- Use a representative log file for the environment you care about.
- For SSH workflows in this project, that’s typically an `ssh_auth`-style log (e.g. LogHub SSH).
- For Apache error workflows, that’s typically an Apache error log (e.g. LogHub Apache).

Example:

```bash
ls data/loghub
SSH.log
Apache.log
```

### Step 2 – Train an Isolation Forest model for SSH

Train on an SSH log and save a model:

```bash
aegislog train \
  --logs-path data/loghub/SSH.log \
  --log-type ssh_auth \
  --model-path models/log_anomaly_iforest_ssh.joblib
```

This will:

- read SSH auth sessions from `data/loghub/SSH.log`,
- build SSH-focused features,
- fit an anomaly model,
- write the model to `models/log_anomaly_iforest_ssh.joblib`.

### Step 2b – Train an Isolation Forest model for Apache error logs

For Apache error logs (e.g. LogHub Apache sample), the workflow is similar. Train on an Apache error log and save a model:

```bash
aegislog train \
  --logs-path data/loghub/Apache.log \
  --log-type apache_error \
  --model-path models/log_anomaly_iforest_apache.joblib
```

This will:

- read Apache error log events from `data/loghub/Apache.log`,
- build sessions and Apache-focused behavioral features (error vs notice ratio, bursts, rare templates, rare hour, etc.),
- fit an anomaly model,
- write the model to `models/log_anomaly_iforest_apache.joblib`.

### Step 3 – Use the model with `analyze`

#### SSH example

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

#### Apache example

```bash
aegislog analyze \
  data/loghub/Apache.log \
  --log-type apache_error \
  --model-path models/log_anomaly_iforest_apache.joblib \
  --threshold-percentile 99 \
  --alerts-only \
  --top 10
```

This runs the Apache error log through the pipeline, scores sessions with your trained Apache model, and prints the top suspicious sessions by anomaly score.

### Step 4 – Use the model with `incidents` (SSH)

Incident grouping is currently focused on SSH (IP-based incidents, auth failure patterns, etc.):

```bash
aegislog incidents \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --model-path models/log_anomaly_iforest_ssh.joblib \
  --threshold-percentile 99 \
  --alerts-only \
  --top 5
```

This will:

- score sessions with the given SSH model,
- filter anomalous sessions (if `--alerts-only`),
- group them into incidents by IP,
- print a summary of the top incidents.

For Apache, you can still use `analyze` (as above) plus the Apache CLI for a simple session-level view (see section 6).

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

- `iforest` + `ssh_auth`      → `models/log_anomaly_iforest_ssh.joblib`
- `iforest` + `apache_error`  → `models/log_anomaly_iforest_apache.joblib`

This lets you maintain separate models for SSH (`ssh_auth`) and Apache error logs (`apache_error`) while using the same CLI commands.

If you train your own model and pass `--model-path`, that explicit path takes precedence over any defaults.

---

## 4. Common usage patterns

### Train once, then reuse (SSH)

For a given SSH environment:

```bash
# 1) Train from representative SSH logs
aegislog train \
  --logs-path /var/log/auth.log \
  --log-type ssh_auth \
  --model-path models/log_anomaly_iforest_prod_ssh.joblib

# 2) Analyze recent logs with your trained SSH model
aegislog analyze \
  /var/log/auth.log \
  --log-type ssh_auth \
  --model-path models/log_anomaly_iforest_prod_ssh.joblib \
  --threshold-percentile 99 \
  --alerts-only

# 3) Group into incidents using the same SSH model
aegislog incidents \
  /var/log/auth.log \
  --log-type ssh_auth \
  --model-path models/log_anomaly_iforest_prod_ssh.joblib \
  --threshold-percentile 99 \
  --alerts-only
```

### Train once, then reuse (Apache error logs)

For a given Apache environment:

```bash
# 1) Train from representative Apache error logs
aegislog train \
  --logs-path /var/log/apache2/error.log \
  --log-type apache_error \
  --model-path models/log_anomaly_iforest_prod_apache.joblib

# 2) Analyze recent Apache error logs with your trained model
aegislog analyze \
  /var/log/apache2/error.log \
  --log-type apache_error \
  --model-path models/log_anomaly_iforest_prod_apache.joblib \
  --threshold-percentile 99 \
  --alerts-only \
  --top 20
```

You can then also use the dedicated Apache CLI to inspect top suspicious sessions (section 6).

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

Similar profiles can be defined for Apache (e.g. `apache_error`) to bind `log_type` and default model paths.

### JSON output for automation

Combine training with machine-readable output for downstream tooling:

```bash
# Analyze SSH logs with a trained model and output JSON
aegislog analyze \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --model-path models/log_anomaly_iforest_ssh.joblib \
  --threshold-percentile 99 \
  --alerts-only \
  --format json \
  --output analyze_ssh.json

# Incidents as JSON (SSH)
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

## 5. Quick reference (SSH)

- Train (SSH):  
  - `aegislog train --logs-path <LOGFILE> --log-type ssh_auth --model-path <MODELFILE>`
- Analyze with custom SSH model:  
  - `aegislog analyze <LOGFILE> --log-type ssh_auth --model-path <MODELFILE>`
- Analyze with thresholding:  
  - `--threshold-percentile 99 --alerts-only`
- Group SSH incidents with the same model:  
  - `aegislog incidents <LOGFILE> --log-type ssh_auth --model-path <MODELFILE>`

---

## 6. Apache error log quick reference

- Train Apache model:  
  ```bash
  aegislog train \
    --logs-path data/loghub/Apache.log \
    --log-type apache_error \
    --model-path models/log_anomaly_iforest_apache.joblib
  ```

- Analyze Apache logs with custom model:  
  ```bash
  aegislog analyze \
    data/loghub/Apache.log \
    --log-type apache_error \
    --model-path models/log_anomaly_iforest_apache.joblib \
    --threshold-percentile 99 \
    --alerts-only \
    --top 20
  ```

- Inspect suspicious Apache sessions via the dedicated CLI (log-based):  
  ```bash
  python -m aegislog.cli_apache data/loghub/Apache.log -n 20
  ```

This CLI:

- Parses `Apache.log` using the Apache error parser.
- Builds sessions and Apache-specific features.
- Scores sessions with the resolved Apache model (or a custom `--model-path` if you extend the CLI).
- Prints the top N suspicious sessions with human-readable notes (e.g. error spikes, rare templates, unusual hours).

---

This cheatsheet now covers both SSH and Apache training and shows how those models flow into `analyze`, `incidents` (for SSH), and the Apache CLI.