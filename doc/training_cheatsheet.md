# Aegislog Training Cheatsheet

This cheatsheet explains how to train anomaly detection models for Aegislog and how those models connect to the `analyze`, `incidents`, `report`, Apache CLI commands, and AI-style explain for SSH.



---

## 1. Command overview

Aegislog exposes training via the CLI:

```bash
aegislog train --logs-path <PATH> --model-path <OUTPUT> [--log-type <TYPE>] [--model-type <NAME>]
```

This is wired to `cmd_train`, which internally calls `aegislog.ml.train.main(...)`.

- `--logs-path`  
  Path to a log file used as training data.
- `--model-path` (optional)  
  Where to save the trained model (defaults depend on `--log-type` / `--model-type`).
- `--log-type` (optional)  
  Log type for feature extraction:
  - `ssh_auth`
  - `apache_error`
- `--model-type` (optional)  
  Anomaly model family:
  - `iforest` (default)
  - `ocsvm`
  - `lof`

The saved model can then be used by:

- `analyze`, `incidents`, and `report` via their `--model-path` / `--model-type` options (SSH + Apache).
- The Apache-specific CLI (`python -m aegislog.cli_apache`) via its `--model-path` / `--model-type` options.
- The SSH `explain` command when building AI-style analysis (`--use-llm`) from scored incidents and evidence.



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
  --model-type iforest \
  --model-path models/log_anomaly_iforest_ssh.joblib
```

This will:

- read SSH auth sessions from `data/loghub/SSH.log`,
- build SSH-focused features,
- fit an Isolation Forest anomaly model,
- write the model to `models/log_anomaly_iforest_ssh.joblib`.

### Step 2b – Train an Isolation Forest model for Apache error logs

For Apache error logs (e.g. LogHub Apache sample), the workflow is similar. Train on an Apache error log and save a model:

```bash
aegislog train \
  --logs-path data/loghub/Apache.log \
  --log-type apache_error \
  --model-type iforest \
  --model-path models/log_anomaly_iforest_apache.joblib
```

This will:

- read Apache error log events from `data/loghub/Apache.log`,
- build sessions and Apache-focused features (error vs notice ratio, bursts, rare templates, rare hour, etc.),
- fit an Isolation Forest anomaly model,
- write the model to `models/log_anomaly_iforest_apache.joblib`.

### Step 2c – Optional: train OCSVM/LOF variants

You can also train alternative models for comparison:

```bash
# SSH OCSVM
aegislog train \
  --logs-path data/loghub/SSH.log \
  --log-type ssh_auth \
  --model-type ocsvm \
  --model-path models/log_anomaly_ocsvm_ssh.joblib

# SSH LOF
aegislog train \
  --logs-path data/loghub/SSH.log \
  --log-type ssh_auth \
  --model-type lof \
  --model-path models/log_anomaly_lof_ssh.joblib

# Apache OCSVM
aegislog train \
  --logs-path data/loghub/Apache.log \
  --log-type apache_error \
  --model-type ocsvm \
  --model-path models/log_anomaly_ocsvm_apache.joblib
```

Later, you can select these via `--model-type` + `--model-path` when analyzing or reporting.



---

## 3. Use the model with `analyze`

### SSH example

```bash
aegislog analyze \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --model-type iforest \
  --model-path models/log_anomaly_iforest_ssh.joblib \
  --top 10
```

Or with percentile thresholding:

```bash
aegislog analyze \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --model-type iforest \
  --model-path models/log_anomaly_iforest_ssh.joblib \
  --threshold-percentile 99 \
  --alerts-only \
  --top 10
```

### Apache example

```bash
aegislog analyze \
  data/loghub/Apache.log \
  --log-type apache_error \
  --model-type iforest \
  --model-path models/log_anomaly_iforest_apache.joblib \
  --threshold-percentile 99 \
  --alerts-only \
  --top 10
```

This runs the Apache error log through the pipeline, scores sessions with your trained Apache model, and prints the top suspicious sessions by anomaly score.



---

## 4. Use the model with `incidents` and `report` (SSH)

Incident grouping is currently focused on SSH (IP-based incidents, auth failure patterns, etc.):

```bash
aegislog incidents \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --model-type iforest \
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

For aggregate metrics:

```bash
aegislog report \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --model-type iforest \
  --model-path models/log_anomaly_iforest_ssh.joblib
```

This uses the same model to summarize sessions and incidents (counts, severity, patterns, etc.).



---

## 5. How training relates to `model-type` and defaults

The CLI supports a `--model-type` flag on `analyze`, `incidents`, `explain`, `report`, and Apache CLI:

```bash
--model-type {iforest, ocsvm, lof}
```

Internally, helpers like `resolve_model_path` pick default model paths based on:

- `log_type` (e.g. `ssh_auth` vs `apache_error`)
- `model_type` (e.g. `iforest`, `ocsvm`, `lof`)

Common defaults (may vary slightly with code):

- `iforest` + `ssh_auth`       → `models/log_anomaly_iforest_ssh.joblib`
- `iforest` + `apache_error`   → `models/log_anomaly_iforest_apache.joblib`

This lets you maintain separate models for SSH and Apache while using the same CLI commands.

If you explicitly pass `--model-path`, that path takes precedence over any defaults.



---

## 6. Apache error log quick reference

### Train Apache model

```bash
aegislog train \
  --logs-path data/loghub/Apache.log \
  --log-type apache_error \
  --model-type iforest \
  --model-path models/log_anomaly_iforest_apache.joblib
```

### Analyze Apache logs with a trained model

```bash
aegislog analyze \
  data/loghub/Apache.log \
  --log-type apache_error \
  --model-type iforest \
  --model-path models/log_anomaly_iforest_apache.joblib \
  --threshold-percentile 99 \
  --alerts-only \
  --top 20
```

### Use the dedicated Apache CLI with the trained model

```bash
# Top suspicious sessions (text)
python -m aegislog.cli_apache \
  data/loghub/Apache.log \
  --model-type iforest \
  --model-path models/log_anomaly_iforest_apache.joblib \
  --top 20

# Explain one suspicious session with evidence (text)
python -m aegislog.cli_apache \
  data/loghub/Apache.log \
  --model-type iforest \
  --model-path models/log_anomaly_iforest_apache.joblib \
  --explain \
  --first

# Aggregate report (JSON)
python -m aegislog.cli_apache \
  data/loghub/Apache.log \
  --model-type iforest \
  --model-path models/log_anomaly_iforest_apache.joblib \
  --report \
  --format json \
  --output apache_report.json
```

Apache CLI will:

- parse the Apache error log,
- build sessions and Apache-specific features,
- score sessions with your chosen model,
- support filters (`--min-score`, `--rare-hour-only`, etc.) and text/JSON output.



---

## 7. SSH AI explain and trained models

The AI-style SSH explain flow (`python -m aegislog.cli explain ... --use-llm`) builds on top of the **same trained SSH models** used for analyze/incidents/report:

1. The model scores sessions in the SSH log.
2. Sessions are grouped into incidents (by IP and auth patterns).
3. Each incident is converted into structured `IncidentEvidence` plus a timeline and aggregate report.
4. An internal AI analysis layer uses this structured evidence (not raw logs) to produce:
   - a natural-language summary,
   - a hypothesis about what is happening,
   - caveats and limitations,
   - recommended next steps,
   - optional playbook suggestions.

The better your SSH model and features, the better the AI analysis will be, because the AI layer leans heavily on anomaly scores, failure ratios, attack pattern classification, and aggregate incident statistics rather than trying to infer everything directly from raw log lines.

To use a specific trained SSH model with AI explain:

```bash
aegislog explain \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --model-type iforest \
  --model-path models/log_anomaly_iforest_ssh.joblib \
  --first \
  --use-llm \
  --format json \
  --output explain_ai.json
```



---

## 8. Quick reference (SSH)

- Train (SSH):  
  `aegislog train --logs-path <LOGFILE> --log-type ssh_auth --model-type iforest --model-path <MODELFILE>`
- Analyze with custom SSH model:  
  `aegislog analyze <LOGFILE> --log-type ssh_auth --model-type iforest --model-path <MODELFILE>`
- Analyze with thresholding:  
  `--threshold-percentile 99 --alerts-only`
- Group SSH incidents with the same model:  
  `aegislog incidents <LOGFILE> --log-type ssh_auth --model-type iforest --model-path <MODELFILE>`
- Report with the same model:  
  `aegislog report <LOGFILE> --log-type ssh_auth --model-type iforest --model-path <MODELFILE>`
- AI-style explain with the same model:  
  `aegislog explain <LOGFILE> --log-type ssh_auth --model-type iforest --model-path <MODELFILE> --use-llm --format json --output explain_ai.json`



---

This cheatsheet now reflects both SSH and Apache training, multi-model support, how trained models are used across `analyze`, `incidents`, `report`, `cli_apache`, and how the SSH AI explain pipeline builds on top of trained models and structured evidence instead of raw log text.