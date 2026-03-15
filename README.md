# AegisLog

AegisLog is an AI-powered log anomaly and triage assistant. It ingests authentication and web access logs, builds per-session and per-IP behavioral features, and uses unsupervised models (Isolation Forest) plus semantic analysis to flag anomalous behavior. On top of detection, AegisLog groups anomalies into incidents and generates short, human-readable explanations to help reduce triage time.

## Features

- Ingests raw auth and access logs (Apache/Nginx-style and JSON app logs).
- Builds per-session and per-IP behavioral features (failed logins, duration, status code patterns, night-time activity, etc.).
- Uses unsupervised anomaly detection (Isolation Forest) to score sessions and IPs without labeled training data.
- Clusters anomalies into higher-level incidents to avoid alert floods.
- Optional AI explainer module that summarizes incidents in natural language (e.g., “Probable credential stuffing from a single IP”).
- Exposes both a CLI and a FastAPI HTTP API for batch analysis.

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