Here’s a focused, realistic TODO list for tomorrow, based on where you are now.

## 1. Manual backend validation

- Hit `/docs` and:
  - Exercise `/normalize` with:
    - `source_type=generic`, `input_format=jsonl` (your sample JSONL).
    - `source_type=generic`, `input_format=syslog` (sample syslog).
  - Exercise `/normalized-incidents` with the same inputs.
  - Exercise `/generic-explain` and `/normalized-explain` with `first=true`, `use_ai=false`.
- Confirm responses match expectations:
  - Summaries look sane.
  - Incidents exist and fields like `event_category`, `event_action`, `severity`, `service`, `user` all show up.
  - Error messages are clear for obviously bad inputs (e.g., empty content).

## 2. Documentation pass

- Update or create:
  - `README.md`:
    - Quickstart (install, run CLI, run API).
    - Example CLI commands for generic/normalized flows.
    - Example API requests (JSON bodies) for each endpoint.
  - `docs/architecture.md`:
    - Verify it matches the final behavior (mapping schema, endpoints, flows).
  - Add or refine mapping docs:
    - Explain `fields` and `defaults` structure.
    - Show one JSON and one YAML example.
- Make sure docs clearly separate:
  - Generic vs normalized flows.
  - CLI usage vs HTTP API usage.

## 3. CI pipeline

- Add a basic workflow (e.g., GitHub Actions) that:
  - Sets up Python and installs dependencies.
  - Runs `python -m pytest`.
- Ensure it:
  - Caches dependencies (optional but nice).
  - Fails the build on any test failure.

## 4. Sample data & examples

- Finalize a small `data/` set:
  - `data/sample_generic.jsonl`
  - `data/sample_syslog.log`
  - `mapping/example_auth_app.yaml`
- Add a short “Examples” section to the README showing:
  - One CLI example using `mapping`.
  - One API example with a `mapping` payload.
  - One normalized explain example (generic or ssh).

## 5. Frontend kickoff

- Create the React app (if not done yet) with Vite.
- Wire up a minimal UI that calls:
  - `/normalize`
  - `/normalized-incidents`
  - `/normalized-explain`
- Hard-code a small sample log textarea for now, just to prove end-to-end flow:
  - Paste sample JSONL.
  - Click “Group incidents.”
  - Click an incident to run explain.
