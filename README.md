# AegisLog

AegisLog is an AI‑powered log analysis and triage service focused on authentication and web access logs. Instead of doing classic supervised classification like SentinelTI, AegisLog uses unsupervised anomaly detection, clustering, and AI explanations to help engineers quickly understand and respond to unusual behavior in their systems.

It lives at the intersection of AI, software engineering, and cybersecurity:

AI: anomaly detection, clustering, semantic log understanding, LLM explanations.

Software engineering: robust pipelines, CLI & API, SQLite tracking, performance for large batches.

Cybersecurity flavor: emphasis on auth attacks, recon/scans, and misconfigurations that have security impact.

## Features

- **Log ingestion and normalization**  
  Ingests raw authentication and web access logs from files or HTTP requests and normalizes them into a consistent event schema (timestamp, IP, user, path, status, user agent, raw text, etc.).

- **Session and IP behavior modeling**  
  Groups individual log events into sessions (user/IP/user‑agent over time) and per‑IP windows, then computes rich behavioral features such as request counts, session duration, failed vs successful login ratios, status code patterns, unique endpoints touched, and after‑hours activity.

- **Unsupervised anomaly detection**  
  Uses unsupervised models (Isolation Forest) trained on mostly normal behavior to assign anomaly scores to each session/IP without needing labeled attack data, and maps scores into risk levels (low/medium/high).

- **Incident clustering instead of alert floods**  
  Clusters related anomalous sessions into higher‑level incidents using behavioral features and optional semantic embeddings of log messages, so you review a handful of incidents instead of thousands of isolated anomalies.

- **LLM‑powered explanations and categories**  
  For each incident, an AI explainer generates short, human‑readable summaries (e.g., “Likely credential stuffing from a single IP”) and proposes a category label such as `auth_attack`, `scanner`, `misconfiguration`, or `app_error`.

- **Security‑flavored behavior detection**  
  Focuses on patterns that matter for security and reliability, including password spraying, credential stuffing, brute‑force login attempts, reconnaissance/scanning of many endpoints, and sudden error spikes on sensitive paths.

- **Triage workflow and feedback loop**  
  Stores incidents, anomaly scores, and explanations in SQLite, and lets analysts mark incidents as “true incident” or “benign,” enabling threshold tuning and simple learning from past triage decisions.

- **Developer‑friendly CLI and HTTP API**  
  Provides a CLI to initialize the database, train models, and analyze log files, plus a FastAPI HTTP API with endpoints for per‑session anomaly detection and incident‑level analysis, suitable for integration into dev, SRE, or SecOps workflows.

- **Experiment tracking and evaluation**  
  Tracks model versions, feature configurations, and evaluation metrics in SQLite so you can compare different anomaly models and feature sets on small labeled benchmarks in a reproducible way.


## Tech stack

- Python 3.10+
- FastAPI for the HTTP API
- scikit-learn for anomaly detection (Isolation Forest)
- SQLite for experiment tracking and triage history
- Pytest for tests
- (Optional) Sentence-transformer / small embedding model for semantic log analysis

## Quick start

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/AegisLog.git
cd AegisLog

2. Create and activate a virtual environment
On Windows (PowerShell):

powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
On Windows (cmd):

text
python -m venv .venv
.\.venv\Scripts\activate.bat
On Linux/macOS:

bash
python -m venv .venv
source .venv/bin/activate
3. Install dependencies
bash
pip install --upgrade pip
pip install -r requirements.txt
(You’ll add requirements.txt soon.)

4. Run the CLI (dev placeholder)
bash
python -m aegislog.cli --help
5. Run the API (dev placeholder)
bash
uvicorn aegislog.api:app --host 0.0.0.0 --port 8080 --reload
CLI (planned)
AegisLog will provide commands for training and detection:

Initialize experiment DB:

bash
python -m aegislog.cli init
Train anomaly model on logs:

bash
python -m aegislog.cli train --logs-path data/train_logs
Analyze a log file and print top incidents (human-readable):

bash
python -m aegislog.cli analyze logs/access.log
Output incidents as JSON for integration:

bash
python -m aegislog.cli analyze logs/access.log --json-pretty
HTTP API (planned)
GET /health – Basic health check.

POST /detect-sessions – Scores sessions/IPs and returns anomaly scores.

POST /detect-incidents – Runs detection, clustering, and explanation to produce incidents.

Authentication: future versions will support an API key via X-API-KEY.

How it works (high level)
Parse logs
Raw auth/access logs are parsed into a normalized event schema (timestamp, IP, user, path, status, user-agent, etc.).

Build behavioral features
Events are grouped into sessions and per-IP windows, and features like event count, duration, failed login ratio, status code pattern, and night-time activity are computed.

Detect anomalies
An Isolation Forest model trained on mostly-normal data assigns an anomaly score to each session/IP. Scores are mapped to risk levels.

Group into incidents
Anomalous sessions/IPs are clustered into incidents so analysts can review a handful of groups instead of thousands of individual events.

Explain incidents (AI explainer)
For each incident, AegisLog summarizes key patterns in natural language and suggests likely categories such as credential stuffing, vulnerability scanning, or misconfiguration.

Project status
Early development. CLI/API commands and models are subject to change.

Author
Name: Dong Quan Tran (Johnny)
GitHub: https://github.com/dong-quan-tran