***

# AegisLog

AegisLog is an AI‑powered log analysis and triage service focused on authentication and web access logs. It combines normalization, incident grouping, and optional AI explanations to help engineers quickly understand and respond to unusual behavior in their systems.

It lives at the intersection of AI, software engineering, and cybersecurity:

- **AI**: anomaly detection, clustering, structured evidence, LLM-style explanations.
- **Software engineering**: robust pipelines, CLI & HTTP API, strong tests.
- **Cybersecurity flavor**: emphasis on auth attacks, recon/scans, and misconfigurations that have security impact.

***

## Features

- **Log ingestion and normalization**  
  Ingests raw authentication and web access logs from files or HTTP requests and normalizes them into a consistent event schema (`NormalizedEvent`: timestamp, IPs, user, host, service, severity, event category/action, raw text, etc.).

- **Generic “bring your own logs” pipeline**  
  Supports generic JSONL and RFC 3164–style syslog, with optional field mappings to adapt arbitrary log formats into the normalized schema.

- **Source‑specific adapters for SSH and Apache**  
  Provides SSH- and Apache-aware parsing, summarization, and incident evidence while reusing the same normalized event model.

- **Incident grouping instead of alert floods**  
  Groups related normalized events into incidents so you review coherent clusters instead of thousands of isolated events.

- **AI‑style explanations and categories**  
  For SSH incidents, Apache sessions, and generic/normalized incidents, AI explain flows take structured evidence and generate human‑readable analyses (summary, hypothesis, caveats, next steps, optional playbook hints).

- **Developer‑friendly CLI and HTTP API**  
  Ships with a CLI for local analysis and automation, plus a FastAPI HTTP API for integrating normalization, incident grouping, and explain flows into other systems (and the upcoming React UI).

***

## Tech stack

- Python 3.10+
- FastAPI for the HTTP API
- scikit-learn for anomaly detection
- SQLite (planned) for experiment tracking and triage history
- Pytest for tests
- Optional embedding/LLM backend for AI explanations

***

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

### 4. Run tests (optional but recommended)

```bash
python -m pytest
```

You should see the full test suite pass.

### 5. Run the CLI

```bash
python -m aegislog.cli --help
```

### 6. Run the HTTP API

```bash
uvicorn aegislog.api:app --host 0.0.0.0 --port 8000 --reload
```

Then open:

- Interactive docs: http://localhost:8000/docs  
- Health check: http://localhost:8000/health

***

## Web UI (React + Vite)

AegisLog includes a simple React UI for interactive triage on top of the HTTP API.

### 1. Start the backend API

In one terminal, from the project root:

```bash
uvicorn aegislog.api:app --host 0.0.0.0 --port 8000 --reload
```

The OpenAPI docs will be available at `http://localhost:8000/docs`.

### 2. Start the frontend (Vite)

The frontend lives in the `aegislog-ui` folder created by Vite.

From the repo root:

```bash
cd aegislog-ui
npm install      # first time only
npm run dev
```

This will start the dev server on `http://localhost:5173`.

During development, Vite proxies `/api/*` requests to the FastAPI backend running on port 8000, so the UI can call endpoints like `/api/normalize` and `/api/normalized-explain` without hardcoding full URLs.

### 3. Using the UI

1. Open `http://localhost:5173` in your browser.
2. Paste JSONL or syslog log content into the **Log content** box (the UI includes a sample JSONL snippet by default).
3. Choose:
   - `source_type` (e.g. `generic`)
   - `input_format` (`jsonl` or `syslog`)
   - `window_minutes` and `top`.
4. Click **Normalize** to see:
   - A summary of total events.
   - Severity and event category/action counts.
5. Click **Group incidents** to:
   - Run the normalized incident grouping.
   - See a list of incidents (severity, priority, event counts).
6. Click an incident to:
   - Fetch a **normalized explain** response.
   - View both the incident object and structured evidence.
7. Check **Use AI explanation** before clicking an incident if you want the backend to attempt AI analysis. The UI will display:
   - `ai_analysis` (structured AI explanation) when available, or
   - `ai_error` when AI is not configured or fails gracefully.

The UI is intended as a thin, developer-friendly layer over the HTTP API to make it easy to demo and debug normalization, incident grouping, and explain flows interactively.

## Bring your own logs (generic pipeline)

AegisLog can normalize **generic logs** into a common schema and then reuse the same incident grouping and explain flows used for SSH and Apache.

Supported generic input formats:

- **JSONL** (`--input-format jsonl`, default): one JSON object per line.
- **Syslog-style text** (`--input-format syslog`): classic RFC 3164 style.

You can optionally provide a **mapping** to adapt your custom fields into AegisLog’s normalized schema.

### Mapping schema

Canonical mapping structure (JSON or YAML):

```yaml
source_type: generic_jsonl
fields:
  timestamp:
    - "@timestamp"
    - "time"
    - "ts"
  src_ip:
    - "client_ip"
    - "ip"
  user:
    - "username"
    - "account"
  message:
    - "msg"
    - "event_message"
  severity:
    - "level"
    - "log_level"
defaults:
  event_category: auth
```

- `fields` maps normalized field names to one or more source aliases.
- `defaults` provides fallback values.
- `source_type` can override the logical label for generic inputs.

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

- parse each JSONL line
- apply the mapping (if provided)
- produce a summary and a preview of normalized events

### Normalize generic syslog

```bash
python -m aegislog.cli normalize \
  data/sample_syslog.log \
  --input-format syslog
```

The syslog parser extracts timestamp, host, severity (from PRI), service/pid (from the tag), and message.

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
  --window-minutes 15 \
  --top 5

# Syslog
python -m aegislog.cli generic-incidents \
  data/sample_syslog.log \
  --input-format syslog \
  --window-minutes 15 \
  --top 5
```

### Explain generic incidents with AI

You can get AI-backed explanations for generic incidents:

```bash
# Explain one generic incident (JSONL)
python -m aegislog.cli generic-explain \
  data/sample_generic.jsonl \
  --index 0 \
  --use-ai \
  --format json \
  --output generic_explain_ai.json

# Explain the first generic incident (syslog)
python -m aegislog.cli generic-explain \
  data/sample_syslog.log \
  --input-format syslog \
  --first \
  --use-ai
```

***

## Normalized incident flows across sources

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
```

Explain a normalized incident with AI:

```bash
python -m aegislog.cli normalized-explain \
  data/sample_generic.jsonl \
  --source-type generic \
  --first \
  --use-ai
```

For `source-type generic`, you can combine `--input-format` (`jsonl` / `syslog`) with an optional `--mapping` file.

***

## HTTP API

The FastAPI layer exposes a small set of endpoints for programmatic access and frontend integration.

### Endpoints

- `GET /health` – Basic health check.
- `POST /normalize` – Normalize logs and compute a summary + preview.
- `POST /generic-incidents` – Group generic logs into incidents.
- `POST /normalized-incidents` – Group normalized events from generic/SSH/Apache into incidents.
- `POST /generic-explain` – Explain a single generic incident (optional AI).
- `POST /normalized-explain` – Explain a single normalized incident (optional AI).

### Request model (simplified)

For `/normalize` and incident endpoints, the base request model looks like:

```json
{
  "content": "<raw log text>",
  "source_type": "generic | ssh | apache",
  "input_format": "jsonl | syslog",
  "mapping": { ... },         // only for source_type="generic"
  "window_minutes": 15,
  "top": 5
}
```

Explain endpoints extend this with:

```json
{
  "index": 0,
  "first": false,
  "use_ai": false
}
```

Validation rules:

- `content` must not be empty.
- `mapping` is only allowed for `source_type="generic"`.
- Unknown fields are rejected.

You can explore and try these endpoints interactively at `/docs` once the server is running.

***

## CLI overview

Main entrypoint:

```bash
python -m aegislog.cli <subcommand> [options]
```

Key subcommands:

- `analyze` – Run session/incident analysis for SSH/Apache.
- `incidents` – Group SSH sessions into incidents.
- `explain`, `ai-explain`, `report` – SSH explain/report flows.
- `normalize`, `normalize-ssh`, `normalize-apache` – Normalization.
- `generic-incidents`, `generic-explain` – Generic pipeline.
- `normalized-incidents`, `normalized-explain` – Normalized pipeline across sources.
- `examples` – Show example command usages.

There is also a dedicated Apache CLI:

```bash
python -m aegislog.cli_apache --help
```

for Apache-focused workflows.

***

## Datasets

AegisLog is developed and tested using subsets of public research datasets from the Loghub collection:

- Apache error logs
- SSH authentication logs

Only small samples are stored in the repo. Larger raw log files are expected to be downloaded by the user for local training and experimentation.

***

## Project status

The **backend** (parsing, normalization, incident grouping, explain flows, CLI, and HTTP API) is implemented and covered by automated tests.

Planned / in progress:

- React frontend for interactive triage on top of the HTTP API.
- SQLite-backed triage store and experiment tracking.
- Additional source-specific adapters and mapping recipes.

***

## Future work

AegisLog is intentionally scoped as a focused MVP. The following improvements are out of scope for this version but are natural next steps:

- **Richer UI workflows**  
  - Add buttons to load built‑in JSONL/syslog/SSH/Apache samples and automatically set `source_type` / `input_format`.  
  - Add a mapping editor panel so generic mappings (JSON/YAML) can be created and tested directly from the UI.  
  - Present explain results in a more human‑friendly layout (headline, key bullets, timeline) instead of raw JSON.

- **Generic grouping and mapping enhancements**  
  - Support additional grouping strategies (e.g., by source IP only, by user only, by host+service).  
  - Extend mapping capabilities with simple transforms (lowercasing, trimming, basic extraction) and better handling of multiple candidate source fields.

- **AI backend flexibility**  
  - Make the AI explain layer pluggable, driven by configuration or environment variables.  
  - Support multiple backends (local models, external APIs) with clear timeouts and error reporting.

- **Observability and testing**  
  - Add structured logging and basic metrics for request volumes, incident counts, and AI success/error rates.  
  - Introduce lightweight frontend tests and, optionally, a multi‑version Python test matrix in CI.

- **Packaging and deployment**  
  - Package AegisLog as an installable Python project with a CLI entry point.  
  - Provide Docker images (API + built frontend) and a simple compose file for local or demo deployments.

## Author

AegisLog is developed and maintained by:

- **Dong Quan Tran (Johnny)**
- Role: Owner / Collaborator
- Email: dxt9721@mavs.uta.edu / dongquan.tran.johnny@gmail.com
- GitHub: dong-quan-tran
