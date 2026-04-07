# AegisLog – Progress Log (2026-03-14)

## High-level decisions

- Defined AegisLog as an **AI-powered log triage assistant** focused on authentication and web access logs, distinct from SentinelTI (URL reputation).
- Chosen approach:
  - Unsupervised anomaly detection (Isolation Forest) on per-session / per-IP behavioral features.
  - Future clustering of anomalies into incidents.
  - Future LLM-based incident explanations and categorization with a security flavor (credential stuffing, scanning, misconfig, etc.).

## README and project positioning

- Wrote a detailed **Features** section emphasizing:
  - Log ingestion and normalization.
  - Session/IP behavior modeling.
  - Unsupervised anomaly detection.
  - Incident clustering.
  - LLM-powered explanations and security-focused behaviors.
  - Triage workflow, feedback loop, CLI + FastAPI API, and experiment tracking.
- Clarified how AegisLog is **different from SentinelTI** in domain, ML style, AI use, and UX.

## Code structure and setup

- Confirmed basic package layout:
  - `aegislog/` with `cli.py`, `api.py`, `parsing/`, `features/`, `ml/`, etc.
- Verified virtual environment setup and ensured `aegislog` is importable.
- Fixed uvicorn import issues by:
  - Ensuring `aegislog/__init__.py` exists.
  - Running uvicorn from the project root with `python -m uvicorn aegislog.api:app --reload`.

## Anomaly engine (first end-to-end slice)

### Data model and parsing

- Added `LogEvent` and `Session` dataclasses in `aegislog/features/sessions.py` to standardize event and session representation.
- Implemented Apache-style access log parsing in `aegislog/parsing/access.py`:
  - Regex-based `parse_access_line`.
  - `parse_access_file(path)` returning a list of `LogEvent` objects.
- Created a small `data/sample_access.log` file with synthetic access log entries for testing.

### Sessionization

- Implemented `build_sessions(events, gap_minutes=30)` in `features/sessions.py`:
  - Sorts events by `(ip, user, user_agent, timestamp)`.
  - Groups events into sessions, splitting on identity changes or time gaps > configured threshold.
  - Produces `Session` objects with `session_id`, `ip`, `user`, `user_agent`, and event list.

### Feature extraction

- Implemented `sessions_to_features` in `aegislog/features/behavioral.py`:
  - For each session, computes:
    - `event_count`
    - `duration_seconds`
    - `status_4xx`
    - `status_5xx`
    - `error_ratio` (4xx+5xx over total events)
  - Returns a pandas DataFrame with one row per session and these numeric features.

### Isolation Forest model and training

- Implemented `build_pipeline` in `aegislog/ml/pipeline.py`:
  - Uses a `ColumnTransformer` + `StandardScaler` over numeric features.
  - Uses `IsolationForest` (unsupervised) with configurable `contamination`.
- Created `aegislog/ml/train.py`:
  - CLI-style script:
    - Parses `--logs-path` and `--model-path`.
    - `parse_access_file` → `build_sessions` → `sessions_to_features`.
    - Fits the Isolation Forest pipeline on the resulting DataFrame.
    - Saves the trained model to `models/log_anomaly_iforest.joblib`.
  - Verified training runs successfully using `data/sample_access.log`.

### Scoring and CLI analyze command

- Extended `ml/pipeline.py` with:
  - `load_model(model_path)` to load the saved pipeline.
  - `score_sessions(sessions, model_path)` to:
    - Build features.
    - Run `decision_function` on the Isolation Forest.
    - Store `anomaly_score = -decision_function` (higher = more anomalous).
- Updated `aegislog/cli.py`:
  - Added `analyze` subcommand:
    - Parses a log file.
    - Runs parsing → sessionization → scoring.
    - Sorts sessions by `anomaly_score` descending.
    - Prints the top N anomalous sessions with basic info (session_id, ip, user, event_count, error_ratio, anomaly_score).
  - Verified end-to-end flow:
    - `python -m aegislog.ml.train --logs-path data/sample_access.log`
    - `python -m aegislog.cli analyze data/sample_access.log --top 3`

## Git / version control

- Initialized git repository (if not already).
- Suggested commit messages:
  - `Add Isolation Forest scoring helper for sessions` (for `ml/pipeline.py` changes).
  - `Add analyze command to score log sessions` (for `cli.py` changes).

## Next steps (future work)

- Enrich behavioral features (failed vs successful logins, path patterns, time-of-day signals).
- Introduce anomaly clustering to convert sessions into incidents.
- Design and implement the LLM-based incident explainer and categories.
- Add FastAPI endpoints that wrap the same detection pipeline.
- Start a Pytest suite for parsing, sessionization, feature extraction, and scoring.


# AegisLog – Progress Log (2026-03-15)

## Dataset choices

- Decided to use **Loghub** datasets as primary data sources for realistic logs: https://github.com/logpai/loghub
  - Apache error logs for web server behavior.
  - OpenSSH / SSH logs for authentication behavior.
- Downloaded and added Loghub files locally under `data/loghub/`:
  - `data/loghub/Apache.log` (Apache error log).
  - `data/loghub/SSH.log` (large SSH log, kept local; sample planned for the repo).
- Noted that `SSH.log` (~69 MB) exceeded GitHub’s recommended size:
  - GitHub accepted the push but warned about file size.
  - Plan: keep a smaller `SSH_sample.log` in the repo and ignore the large raw file via `.gitignore`.

## Apache error log parsing

- Recognized that Loghub’s Apache dataset is an **error log**, not an HTTP access log.
- Implemented a dedicated Apache error-log parser in `aegislog/parsing/apache_error.py`:
  - `parse_error_line(line)`:
    - Parses lines like `[Thu Jun 09 06:07:04 2005] [notice] ...`.
    - Extracts timestamp and log level (`notice`, `error`, etc.).
    - Stores log level temporarily in `LogEvent.user_agent` (to be used as a feature).
  - `parse_error_file(path)`:
    - Reads the file and converts each line into a `LogEvent` with:
      - `timestamp`, `level` (via `user_agent`), `source="apache_error"`, and raw text.
- Updated training and CLI paths to use `parse_error_file` when working with `data/loghub/Apache.log`.

## Session feature engineering

- Extended `aegislog/features/behavioral.py` to compute richer per-session features using Apache error logs:
  - Existing features:
    - `event_count` – number of events in the session.
    - `duration_seconds` – time difference between first and last event.
    - `status_4xx`, `status_5xx` – HTTP status buckets (usually empty for error logs).
    - `error_ratio` – (4xx + 5xx) / total events.
  - New features based on log levels:
    - `error_events` – count of events with level `"error"`.
    - `notice_events` – count of events with level `"notice"`.
    - `error_event_ratio` – `error_events / event_count`.
  - Ensured `sessions_to_features` returns a DataFrame with:
    - `session_id`, `ip`, `user`, `event_count`, `duration_seconds`,
      `status_4xx`, `status_5xx`, `error_ratio`,
      `error_events`, `notice_events`, `error_event_ratio`.

## ML pipeline updates

- Updated `aegislog/ml/pipeline.py`:
  - Extended `NUMERIC_FEATURES` to include the new error-level features:
    - `["event_count", "duration_seconds", "status_4xx", "status_5xx", "error_ratio",
       "error_events", "notice_events", "error_event_ratio"]`.
  - Kept the Isolation Forest pipeline structure:
    - `ColumnTransformer` + `StandardScaler` over numeric features.
    - `IsolationForest` with fixed `random_state` and configurable `contamination`.
  - Confirmed alignment between `NUMERIC_FEATURES` and columns produced by `sessions_to_features`.

## Training and analysis on Loghub Apache

- Successfully trained a model on Loghub Apache error logs:

  ```bash
  python -m aegislog.ml.train --logs-path "data/loghub/Apache.log" --model-path models/log_anomaly_iforest_apache.joblib

  python -m aegislog.cli analyze "data/loghub/Apache.log" --model-path models/log_anomaly_iforest_apache.joblib --top 5

![alt text](<Screenshot 2026-03-15 164616.png>)


# AegisLog – Progress Log (2026-03-17)

## SSH authentication parsing and pipeline integration

- Implemented a dedicated SSH/authentication parser (`parsing/auth_ssh.py`) for Loghub SSH logs:
  - Parses standard OpenSSH-style lines like:
    - `Dec 10 06:55:46 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2`
  - Extracts:
    - `timestamp` (assumed year 2005 for ordering),
    - `ip` from the `from <ip>` portion,
    - `user` when present in patterns like `user <name>`,
    - `status` as a simple auth outcome:
      - `401` for “Failed password …” lines,
      - `200` for “Accepted password …” lines,
    - `source="ssh_auth"` to distinguish from other log types.

- Verified that the SSH parser works by:
  - Loading `data/loghub/SSH.log`:
    - ~655k events parsed into `LogEvent` objects.
  - Building sessions (`build_sessions`) and features (`sessions_to_features`) on top of these events:
    - ~18k sessions created.
    - Confirmed feature columns include:
      - `event_count`, `duration_seconds`,
      - `status_4xx`, `status_5xx`, `error_ratio`,
      - `error_events`, `notice_events`, `error_event_ratio`,
      - plus new auth-specific fields.

## SSH-specific behavioral features

- Extended `sessions_to_features` in `features/behavioral.py` with SSH/auth features:
  - `auth_failed` – count of events with `status == 401` in the session.
  - `auth_success` – count of events with `status == 200`.
  - `auth_fail_ratio` – `auth_failed / (auth_failed + auth_success)` when there are any auth events.
- These features are designed to highlight suspicious auth behavior such as:
  - Sessions with only failures (`auth_fail_ratio` close to 1).
  - Sessions with many failures before a success (potential brute-force or credential stuffing).

## ML pipeline updates for multi-log support

- Updated `ml/pipeline.py` to include the new SSH features in the numeric feature set:
  - `NUMERIC_FEATURES` now includes:
    - `event_count`, `duration_seconds`,
      `status_4xx`, `status_5xx`, `error_ratio`,
      `error_events`, `notice_events`, `error_event_ratio`,
      `auth_failed`, `auth_success`, `auth_fail_ratio`.
- Modified `ml/train.py` to accept a `--log-type` flag:
  - `--log-type apache_error` → uses `parse_error_file` for Loghub Apache error logs.
  - `--log-type ssh_auth` → uses `parse_ssh_file` for Loghub SSH logs.
- Trained and saved separate models:
  - Apache error log model:
    - `python -m aegislog.ml.train --logs-path data/loghub/Apache.log --log-type apache_error --model-path models/log_anomaly_iforest_apache.joblib`
  - SSH auth model:
    - `python -m aegislog.ml.train --logs-path data/loghub/SSH.log --log-type ssh_auth --model-path models/log_anomaly_iforest_ssh.joblib`

## CLI support for Apache and SSH

- Updated `cli.py` `analyze` command to accept a `--log-type` flag:
  - `--log-type apache_error`:
    - Parses `Apache.log` via the Apache error parser.
    - Scores sessions with the Apache Isolation Forest model.
  - `--log-type ssh_auth`:
    - Parses `SSH.log` via the SSH auth parser.
    - Scores sessions with the SSH Isolation Forest model.
- Verified both flows:
  - Apache:
    - `python -m aegislog.cli analyze data/loghub/Apache.log --log-type apache_error --model-path models/log_anomaly_iforest_apache.joblib --top 3`
  - SSH:
    - `python -m aegislog.cli analyze data/loghub/SSH.log --log-type ssh_auth --model-path models/log_anomaly_iforest_ssh.joblib --top 3`
  - Confirmed that SSH output shows high-event sessions per IP with `error_ratio` and anomaly scores.

## README updates

- Added a **Datasets** section describing the use of Loghub:
  - Apache error logs for web server error behavior.
  - SSH authentication logs for auth behavior (failed/successful logins).
  - Noted that only small samples are stored in the repo; full datasets are expected to be downloaded locally.

## Overall status

- AegisLog now supports:
  - Apache error logs and SSH authentication logs from Loghub.
  - Session-based feature extraction with both error-level and auth-specific metrics.
  - Separate Isolation Forest models for different log types.
  - A CLI that can analyze both Apache and SSH logs with a `--log-type` switch.

  ![alt text](image.png)

- Next steps:
  - Refine SSH features (e.g., per-IP vs per-user session definitions).
  - Start grouping high-scoring sessions into simple incident clusters (e.g., per-IP incidents).
  - Design and implement the first version of the incident + explanation API.


# Progress Log

## 2026-03-18

### SSH session and incident enrichment

- Added SSH authentication statistics to session features, tracking failed and successful authentication attempts per session and exposing them to the anomaly scoring pipeline as `auth_failed` and `auth_success`.
- Updated IP-based incident aggregation to use authentication data:
  - Grouped sessions by source IP.
  - Aggregated total events, average anomaly score, total `auth_failed`, total `auth_success`, and computed an `auth_fail_ratio` per IP.
- Extended the `Incident` model to store:
  - `auth_failed`
  - `auth_success`
  - `auth_fail_ratio`
  so incidents carry security-relevant SSH auth context.

### CLI: incidents output with auth stats

- Enhanced the `incidents` CLI command to show SSH authentication statistics per incident:
  - Printed `auth_failed`, `auth_success`, and `auth_fail_ratio` in addition to existing fields such as `incident_id`, `ip`, `sessions`, `total_events`, and `avg_anomaly_score`.
- Confirmed that the top IP-based incidents surfaced in the CLI correspond to noisy SSH activity patterns consistent with brute-force attempts (high failed-auth counts, no successes).

---

## 2026-03-19

### Incident severity heuristic

- Extended the `Incident` dataclass with a `severity` field representing a simple textual risk level for each SSH incident.
- Implemented a `_compute_severity` helper function that derives severity from:
  - Average anomaly score.
  - Total failed authentication attempts.
  - Authentication failure ratio.
- Defined an initial heuristic:
  - Mark incidents with very high failed-auth counts, near-100% failure ratio, and elevated anomaly score as `"high"` severity.
  - Mark moderately suspicious auth behavior as `"medium"`.
  - Default remaining activity to `"low"`.

### CLI: severity in incidents output

- Updated `group_sessions_by_ip` to compute and attach a severity level for each IP-based incident using the aggregated SSH auth stats and anomaly scores.
- Enhanced the `incidents` CLI output format to include the new `severity` field:
  - Example output now includes:  
    `severity=<low|medium|high> sessions=... total_events=... auth_failed=... auth_success=... auth_fail_ratio=... avg_anomaly_score=...`
- Verified against `data/loghub/SSH.log` that top IP-based incidents with large numbers of failed SSH logins and zero successes are labeled as `severity=high`, matching expectations for brute-force style SSH scanning behavior.

## 2026-03-20

### AI-ready incident prompts

- Introduced a new `aegislog.ai` module that builds **LLM-ready prompts** for SSH incidents using structured incident data (IP, severity, events, auth stats, anomaly score) plus the existing human-written summary. The prompt guides an AI assistant to explain what is happening, assess brute-force behavior, and suggest next steps for a junior analyst.
- Defined an `LLMIncidentPrompt` dataclass and a `build_incident_llm_prompt()` helper that returns a complete incident explanation prompt string without making any external API calls, creating a clean integration surface for future LLM clients.
- Added an `explain_incident_with_llm()` placeholder that currently just echoes the prompt text, keeping logic for building prompts and invoking models clearly separated for future implementation.

### CLI: inspect LLM prompts for incidents

- Extended the `incidents` CLI command with a `--print-llm-prompt` flag; when enabled, the CLI prints a fully formatted, ready-to-send LLM prompt between `llm_prompt_begin` and `llm_prompt_end` for each top SSH incident. This makes it easy to copy/paste directly into an LLM for manual testing.
- Wired the AI helper into `cmd_incidents`: after printing the incident fields and rule-based summary, the command now optionally generates and displays the LLM prompt built from the same data, aligning with patterns used in recent work on LLM-based event log analysis and incident summarization.
- Manually validated the end-to-end flow by running the `incidents` command with `--print-llm-prompt` against `data/loghub/SSH.log`, confirming that high-severity brute-force style SSH incidents produce clear summaries and detailed prompts suitable for AI-driven explanations.

![alt text](image-1.png)

![alt text](image-2.png)

![alt text](image-3.png)

## 2026-03-21

### Incident time windows

- Extended the `Incident` model to record `first_seen` and `last_seen` timestamps for each SSH incident, giving every IP-based incident a clear time window. This follows common SIEM and threat-modeling patterns that track when suspicious activity starts and ends to support investigations and correlation.
- Updated the incident aggregation logic to derive `first_seen` and `last_seen` by scanning all events in the sessions associated with each IP, so the time bounds accurately reflect the observed SSH activity rather than a single log line.

### CLI and summaries with time context

- Enhanced the `incidents` CLI output to display a `time_window=<first_seen>..<last_seen>` field alongside severity, event counts, and auth statistics, making it easier to see when a brute-force-style SSH pattern occurred.
- Improved `summarize_incident` to include a short, human-readable sentence describing the timeframe of each incident (for example, “This activity was observed between <first_seen> and <last_seen>.”), aligning the summaries more closely with how analysts describe SSH brute-force campaigns.

### LLM prompts enriched with timestamps

- Updated the LLM incident prompt builder in `aegislog.ai` to include `First seen` and `Last seen` lines in the structured incident context whenever timestamps are available, so any future AI explainer can reason about the duration and timing of suspicious SSH activity.
- Verified that the `--print-llm-prompt` option in the `incidents` CLI now produces prompts that contain IP, severity, auth statistics, anomaly scores, and the incident time window, making the prompts more informative and in line with best practices for LLM-based security incident analysis.

![alt text](image-4.png)

## 2026-03-22

### Rule-based incident recommendations

- Added a `recommend_incident_actions()` helper for SSH incidents that suggests simple, playbook-style next steps based on incident characteristics (e.g., high failed-auth counts with no successes). The helper recommends blocking or rate-limiting abusive IPs and reviewing targeted accounts, aligning with common SSH brute-force response guidance.
- Integrated recommended actions into `summarize_incident`, appending a concise “Recommended actions:” section to the incident description so summaries now include both what happened and what to do next.

### AI prompts enriched with actions

- Updated the LLM incident prompt builder in `aegislog.ai` to include a “Here are preliminary, rule-based recommended actions” block populated from `recommend_incident_actions()`, giving any future LLM a concrete starting set of remediation ideas to refine. This mirrors how many AI SOC tools pair structured data with canned guidance in their prompts.
- Verified that `--print-llm-prompt` output for SSH incidents now contains both the time window and recommended actions, making the prompts more informative and closer to real-world AI incident copilot designs.

### Local AI-style explanations and explain subcommand

- Implemented a `local_incident_explanation()` helper that generates a short, rule-based narrative for each SSH incident (severity, behavior, timing, and recommended actions), mimicking an AI-generated explanation without calling any external model.
- Extended the `incidents` CLI command with a `--show-local-explanation` flag that prints the local explanation between `local_explanation_begin` and `local_explanation_end`, next to the structured incident fields and summary.
- Introduced a new `explain` subcommand that focuses on a single SSH incident selected by index, printing its core fields, summary, local AI-style explanation, and an LLM-ready prompt bundle in one place. This subcommand acts as a small “incident copilot” interface on top of the existing detection pipeline.

![alt text](image-5.png)

## 2026-03-23

### AI helpers and incident modeling cleanup

- Refined the `Incident` model and aggregation logic in `incidents.py` for clarity and consistency, tightening types, formatting, and severity heuristics while preserving behavior (including auth stats, time window, and recommended actions). This makes the incident representation cleaner and easier to extend.
- Polished `summarize_incident()` and `recommend_incident_actions()` so that brute-force hints, time window, and recommended actions are composed into a single well-formed paragraph, improving readability for both humans and downstream AI consumers.

### AI prompt and local explanation improvements

- Cleaned up `aegislog.ai` by simplifying `local_incident_explanation()` into a concise 2–4 sentence narrative that describes severity, behavior, timing, and next steps, making the local, rule-based “AI-style” explanation more readable and closer to real LLM output.
- Simplified `build_incident_llm_prompt()` to reuse `recommend_incident_actions()` when building the “preliminary, rule-based recommended actions” block and tightened string assembly, resulting in a clearer, easier-to-maintain incident prompt template.

### CLI explain/incidents command cleanup and JSON output

- Refactored the `incidents` and `explain` commands in `cli.py` to remove duplicate LLM prompt printing, ensure the incident `time_window` is displayed, and consistently use the shared helpers for summaries, local explanations, and prompts. This keeps the CLI behavior predictable and AI-ready.
- Added a `--format json` option to the `explain` command that emits a single structured JSON object containing the incident fields, summary, local explanation, and LLM prompt. This enables easy integration with other tools, scripts, or notebooks that want to consume AI-ready incident context programmatically.

![alt text](image-6.png)

![alt text](image-7.png)


## 2026-03-29

**Focus:** AegisLog CLI UX, JSON output, and documentation.

### Completed
- Reviewed and understood existing `aegislog.cli` subcommands (`init`, `train`, `analyze`, `incidents`, `explain`), including `--log-type` and `--model-path` usage.
- Extended the `incidents` subcommand to support `--format json`, returning:
  - `incident` metadata (IP, severity, timestamps, auth stats, anomaly score).
  - `summary` (title + description).
  - `local_explanation` (rule-based AI-style explanation).
  - `llm_prompt` (ready-to-send LLM prompt).
- Verified `incidents --format json` against `data/loghub/SSH.log` with:
  - `--log-type ssh_auth`
  - `--model-path models/log_anomaly_iforest_ssh.joblib`
  - `--top 3`
- Confirmed that `explain` already supports `--format json` and validated example output.
- Created `cli_usage_cheatsheet.md` draft documenting:
  - All 5 subcommands.
  - Key arguments (`--log-type`, `--model-path`, `--top`, `--format`, `--use-llm`, etc.).
  - Copy-pasteable example commands for each subcommand.

### Notes / Learnings
- `analyze` supports both `apache_error` and `ssh_auth` log types using the general model `models/log_anomaly_iforest.joblib`.
- `incidents` and `explain` are currently SSH-only (`ssh_auth`) and use the SSH-specific model `models/log_anomaly_iforest_ssh.joblib`.
- JSON output for both `incidents` and `explain` is now suitable for downstream automation and LLM-based workflows.

### Next Ideas
- Add PowerShell-specific examples (with backticks) alongside the bash examples in the CLI cheatsheet.
- Implement and wire up the `init` subcommand to actually set up a SQLite experiment database.
- Add basic unit/integration tests for `incidents --format json` and `explain --format json` to guard against regressions.

![alt text](image-8.png)


## 2026-04-01

**Focus:** AegisLog CLI improvements, structured output consistency, and maintainability.

### Completed
- Added JSON output support to the `analyze` command with `--format json`.
- Added optional file output support to `analyze` via `--output`, allowing JSON results to be written directly to disk.
- Fixed JSON serialization for `analyze` so missing values like `NaN` are normalized to proper JSON `null`.
- Added optional file output support to `incidents --format json` via `--output`.
- Added optional file output support to `explain --format json` via `--output`.
- Improved top-level CLI help output with a clearer description and example commands.
- Refactored repeated JSON serialization and output-writing logic into reusable helpers in `cli.py`.

### Verified
- Confirmed `analyze --format json --output analyze.json` works with SSH logs and produces structured session output.
- Confirmed `incidents --format json --output incidents.json` writes complete incident bundles, including summaries, local explanations, and LLM prompts.
- Confirmed `explain --format json --output explain.json` writes a single-incident explanation bundle correctly.
- Confirmed `python -m aegislog.cli -h`, `analyze -h`, `incidents -h`, and `explain -h` display the updated help text as expected.

### Notes
- `analyze` initially failed with `--format json` because the parser option had not yet been added to `p_analyze`; this was fixed by wiring the flag into argparse.
- A `payload is not defined` error occurred when JSON writing logic was placed in `main()` instead of inside the command handler; this was fixed by moving output handling into the appropriate command functions.
- SSH analysis output showed `user: null`, which is now valid JSON and preferable to raw `NaN`.

### Commits made
- Added output file support to `analyze` JSON output.
- Normalized NaN fields to null in `analyze` JSON output.
- Added output file support to `incidents` JSON output.
- Added output file support to `explain` JSON output.
- Improved CLI help text and examples.
- Refactored CLI JSON serialization helpers.

![alt text](image-9.png)

![alt text](image-10.png)

### Next ideas
- Add tests for CLI JSON helper functions and output-writing behavior.
- Add integration-style tests for `analyze`, `incidents`, and `explain` JSON modes.
- Consider adding `--output` support to future structured-output commands by default for consistency.

### Progress log: 04/05/2026

## Session structure and building
- Extended `Session` to include `start_time`, `end_time`, and `source_set` so each session has explicit time bounds and source metadata.  
- Updated `build_sessions()` to:
  - Use a stable, timestamp-based `session_id` format.
  - Populate `start_time`, `end_time`, and `source_set` when flushing sessions.

## Behavioral features and model inputs
- Updated `sessions_to_features()` to:
  - Use `s.start_time`/`s.end_time` instead of recomputing from events.
  - Fix variable name bugs in `avg_events_per_second` and `unique_paths`.
  - Add new features:
    - `avg_events_per_second`
    - `unique_paths`
    - `source_count`
    - `has_mixed_sources`
- Updated `NUMERIC_FEATURES` in `pipeline.py` to include:
  - `avg_events_per_second`
  - `unique_paths`
  - `source_count`
  - `has_mixed_sources`
- Note: retraining the IsolationForest model is now required to align with the new feature schema.

## Incident grouping and severity
- Renamed and refactored incident grouping from IP-only to principal-aware:
  - New function `group_sessions_to_incidents(...)` groups by `(ip, user)` when possible, falling back to IP only.
  - Added a `merge_window_minutes` parameter (default 60) and implemented time-window clustering so nearby sessions from the same principal form a single incident.
- Enhanced `Incident` dataclass:
  - Added `has_success_after_failures: bool`.
- Incident logic improvements:
  - Compute `has_success_after_failures` at cluster level (`auth_failed > 0 and auth_success > 0`).
  - Extended `_compute_severity(...)` to accept `has_success_after_failures` and treat “failed then successful logins” as a strong high-severity signal under reasonable anomaly/volume thresholds.
  - Updated severity call sites to pass this flag.
- Summary and actions:
  - Added compromise hint text in `summarize_incident(...)` when `has_success_after_failures` is true.
  - Existing recommended actions still apply, with better context from the new flags and severity logic.

## Commit messages used / suggested
- `Add avg_events_per_second and unique_paths features to session behavioral vectors`
- `Update anomaly detection pipeline to include new behavioral features`
- `Enhance Session model with start/end timestamps and source metadata`
- `Group incidents by IP and user context instead of IP alone`
- `Add time-window incident merging for related sessions`
- `Flag incidents with successful logins after failed auth attempts`
