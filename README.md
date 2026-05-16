# AegisLog

AegisLog is an AI‑powered log analysis and triage service focused on authentication and web access logs. Instead of doing classic supervised classification like SentinelTI, AegisLog uses unsupervised anomaly detection, clustering, and AI explanations to help engineers quickly understand and respond to unusual behavior in their systems.

It lives at the intersection of AI, software engineering, and cybersecurity:

- **AI**: anomaly detection, clustering, semantic-log-style evidence, LLM-style structured explanations.
- **Software engineering**: robust pipelines, CLI & API, SQLite tracking, performance for large batches.
- **Cybersecurity flavor**: emphasis on auth attacks, recon/scans, and misconfigurations that have security impact.

## Features

- **Log ingestion and normalization**  
  Ingests raw authentication and web access logs from files or HTTP requests and normalizes them into a consistent event schema (timestamp, IP, user, path, status, user agent, raw text, etc.).

- **Session and IP behavior modeling**  
  Groups individual log events into sessions (user/IP/user‑agent over time) and per‑IP windows, then computes rich behavioral features such as request counts, session duration, failed vs successful login ratios, status code patterns, unique endpoints touched, and after‑hours activity.

- **Unsupervised anomaly detection**  
  Uses unsupervised models (Isolation Forest, with options for other anomaly models) trained on mostly normal behavior to assign anomaly scores to each session/IP without needing labeled attack data, and maps scores into risk levels (low/medium/high).

- **Incident clustering instead of alert floods**  
  For SSH authentication logs, clusters related anomalous sessions into higher‑level incidents so you review a handful of incidents instead of thousands of isolated anomalies.

- **LLM‑style explanations and categories**  
  For SSH incidents, Apache sessions, and normalized generic incidents, AI-style explain flows build structured evidence from anomaly scores and features, then generate human‑readable analyses (e.g., “Likely credential stuffing from a single IP”) plus hypotheses, caveats, and next‑step recommendations.

- **Security‑flavored behavior detection**  
  Focuses on patterns that matter for security and reliability, including password spraying, credential stuffing, brute‑force login attempts, reconnaissance/scanning of many endpoints, and sudden error spikes on sensitive paths.

- **Triage workflow and feedback loop** *(planned)*  
  Will store incidents, anomaly scores, and explanations in SQLite, and let analysts mark incidents as “true incident” or “benign,” enabling threshold tuning and simple learning from past triage decisions.

- **Developer‑friendly CLI and HTTP API**  
  Provides a CLI to train models and analyze log files today, and a FastAPI HTTP API is planned for per‑session anomaly detection and incident‑level analysis, suitable for integration into dev, SRE, or SecOps workflows.

- **Experiment tracking and evaluation** *(planned)*  
  Will track model versions, feature configurations, and evaluation metrics in SQLite so you can compare different anomaly models and feature sets on small labeled benchmarks in a reproducible way.

## Tech stack

- Python 3.10+
- FastAPI for the HTTP API
- scikit-learn for anomaly detection (Isolation Forest and variants)
- SQLite for experiment tracking and triage history
- Pytest for tests
- (Optional) Sentence-transformer / small embedding model for semantic log analysis

## Quick start

### 1. Clone the repository

```bash
git clone https://github.com/dong-quan-tran/AegisLog.git
cd AegisLog
```

### 2. Create and activate a virtual environment

On Windows (PowerShell):

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

On Windows (cmd):

```cmd
python -m venv .venv
.\.venv\Scripts\activate.bat
```

On Linux/macOS:

```bash
python -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Run the CLI

```bash
python -m aegislog.cli --help
```

### 5. Run the API (dev placeholder)

```bash
uvicorn aegislog.api:app --host 0.0.0.0 --port 8080 --reload
```

## Bring your own logs

AegisLog can normalize **generic logs** into a common schema, then reuse the same incident grouping and AI explanation flows you get for SSH and Apache.

Two main input formats are supported:

- **JSONL** (`--input-format jsonl`, default): one JSON object per line.
- **Syslog-style text** (`--input-format syslog`): classic RFC 3164 style with a `<PRI>` prefix, timestamp, hostname, and message.

You can optionally provide a **field mapping** to adapt your custom fields into AegisLog’s normalized schema.

### Normalize generic JSONL

Basic normalization:

```bash
python -m aegislog.cli normalize data/sample_generic.jsonl
```

With a mapping file:

```bash
python -m aegislog.cli normalize \
  data/sample_generic.jsonl \
  --mapping mapping/example_auth_app.yaml
```

This will:

- parse each JSONL line,
- apply the mapping (if provided) into the normalized event schema,
- print a summary plus a preview of normalized events.

### Normalize generic syslog

```bash
python -m aegislog.cli normalize \
  data/sample_syslog.log \
  --input-format syslog
```

The syslog parser extracts basic fields such as timestamp, host, severity/level, and message from RFC 3164–style headers.

### Group generic events into incidents

Once normalized, you can group generic events into incidents:

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

### Explain generic incidents with AI

You can get AI-backed explanations for generic incidents, similar to SSH/Apache:

```bash
# Explain one generic incident (JSONL)
python -m aegislog.cli generic-explain \
  data/sample_generic.jsonl \
  --index 0 \
  --use-ai \
  --format json \
  --output generic_explain_ai.json

# Explain one generic incident (syslog)
python -m aegislog.cli generic-explain \
  data/sample_syslog.log \
  --input-format syslog \
  --first \
  --use-ai
```

### Normalized incident flows across sources

AegisLog can also operate directly on normalized events from SSH, Apache, and generic logs:

```bash
# Group normalized events into incidents
python -m aegislog.cli normalized-incidents \
  data/sample_generic.jsonl \
  --source-type generic

python -m aegislog.cli normalized-incidents \
  data/loghub/SSH.log \
  --source-type ssh

python -m aegislog.cli normalized-incidents \
  data/loghub/Apache.log \
  --source-type apache

# Explain a normalized incident with AI
python -m aegislog.cli normalized-explain \
  data/sample_generic.jsonl \
  --source-type generic \
  --first \
  --use-ai
```

For `source-type generic`, you can combine `--input-format` (`jsonl` / `syslog`) with an optional `--mapping` file.

## CLI

Main entrypoint:

```bash
python -m aegislog.cli <subcommand> [options]
```

Current subcommands:

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

Additional Apache‑specific CLI:

- `cli_apache` (run via `python -m aegislog.cli_apache`)

### Common CLI examples

Analyze a log file and print top anomalous sessions (human‑readable):

```bash
# Apache error log
python -m aegislog.cli analyze data/loghub/Apache.log --log-type apache_error

# SSH auth log
python -m aegislog.cli analyze data/loghub/SSH.log --log-type ssh_auth
```

Group anomalous SSH sessions into incidents:

```bash
python -m aegislog.cli incidents \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --min-severity medium \
  --top 5
```

Explain a single SSH incident, optionally with AI‑style analysis:

```bash
# Evidence-style explain (no AI analysis)
python -m aegislog.cli explain \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --min-severity high \
  --first

# AI-augmented explain JSON bundle
python -m aegislog.cli explain \
  data/loghub/SSH.log \
  --log-type ssh_auth \
  --first \
  --use-llm \
  --format json \
  --output explain_ai.json
```

Use the dedicated Apache CLI to inspect sessions, explain one, see a report, or get AI analysis:

```bash
# Top suspicious sessions (text)
python -m aegislog.cli_apache data/loghub/Apache.log --top 20

# Explain a single suspicious Apache session with evidence
python -m aegislog.cli_apache \
  data/loghub/Apache.log \
  --explain \
  --first

# Aggregate Apache report
python -m aegislog.cli_apache \
  data/loghub/Apache.log \
  --report

# AI-augmented Apache explain (structured analysis)
python -m aegislog.cli_apache \
  data/loghub/Apache.log \
  --ai-explain \
  --first \
  --format json \
  --output apache_explain_ai.json
```

For generic logs and normalized flows, see `cli_usage_cheatsheet.md` for a more detailed walkthrough.

### When to use explain vs AI explain

- Use `explain` / `--explain` (SSH and Apache) when you want deterministic, evidence‑style output that directly reflects anomaly scores and features.
- Use AI explain:
  - SSH: `--use-llm` with `aegislog explain`
  - Apache: `--ai-explain` with `cli_apache`
  - Generic: `--use-ai` with `generic-explain` or `normalized-explain --source-type generic`  
  when you want structured narrative analysis, hypotheses, and recommended next steps generated from that evidence.

## HTTP API (planned)

- `GET /health` – Basic health check.
- `POST /detect-sessions` – Scores sessions/IPs and returns anomaly scores.
- `POST /detect-incidents` – Runs detection, clustering, and explanation to produce incidents.

Authentication: future versions will support an API key via `X-API-KEY`.

## Datasets

AegisLog is developed and tested using subsets of public research datasets from the Loghub collection (https://github.com/logpai/loghub):

- **Apache error logs** – used to model abnormal web server error behavior over time (e.g., bursts of `[error]` vs `[notice]` events).
- **SSH authentication logs** – used to model authentication behavior such as repeated failed login attempts from the same IP or across many users.

Only small samples of these datasets are stored in the repository. Larger raw log files (for example, the full Loghub SSH log) are expected to be downloaded locally by the user for training and experimentation.

## How it works (high level)

1. **Parse logs**  
   Raw auth/access logs are parsed into a normalized event schema (timestamp, IP, user, path, status, user-agent, etc.).

2. **Build behavioral features**  
   Events are grouped into sessions and per-IP windows, and features like event count, duration, failed login ratio, status code pattern, and night-time activity are computed.

3. **Detect anomalies**  
   An Isolation Forest model (and optional variants) trained on mostly-normal data assigns an anomaly score to each session/IP. Scores are mapped to risk levels.

4. **Group into incidents**  
   For SSH, anomalous sessions/IPs are clustered into incidents so analysts can review a handful of groups instead of thousands of individual events. For generic/normalized logs, heuristic grouping runs directly on normalized events.

5. **Explain incidents and sessions (AI explainer)**  
   For SSH incidents, selected Apache sessions, and generic/normalized incidents, AegisLog builds structured evidence and, when enabled, runs AI-style analysis to summarize patterns, propose likely categories, and recommend investigation steps.

## Project status

Early development. CLI/API commands and models are evolving as AI and detection features are iterated.

## Author

Name: Dong Quan Tran (Johnny)  
GitHub: https://github.com/dong-quan-tran