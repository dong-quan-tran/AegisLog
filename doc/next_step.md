# NEXT_STEPS_GENERIC_LOGS.md

# AegisLog Generic Log Support Plan

## Goal

Make AegisLog usable on user-provided logs by introducing a normalization layer and a generic analysis path, instead of limiting the project to SSH and Apache only.

---

## Phase 1 — Normalized schema

- [ ] Create a new normalized event schema for all supported logs.
- [ ] Keep the first version intentionally small and stable.
- [ ] Required fields:
  - [ ] timestamp
  - [ ] source_type
  - [ ] raw_message
  - [ ] event_category
  - [ ] event_action
  - [ ] severity
  - [ ] src_ip
  - [ ] dst_ip
  - [ ] user
  - [ ] host
  - [ ] service
  - [ ] status_code
  - [ ] message
  - [ ] session_hint
  - [ ] extra
- [ ] Decide representation:
  - [ ] dataclass
  - [ ] TypedDict
  - [ ] pandas row contract
- [ ] Add one canonical helper that converts normalized events to dictionaries for JSON output.

### Done when
- [ ] Every later parser can target one shared schema.
- [ ] Existing SSH and Apache code can be mapped into it.

---

## Phase 2 — Source adapters

- [ ] Keep SSH as adapter #1.
- [ ] Keep Apache as adapter #2.
- [ ] Add a new generic parser entrypoint for user logs.
- [ ] Support at least these input styles first:
  - [ ] JSON lines
  - [ ] simple delimited text
  - [ ] syslog-like plain text
- [ ] Add format detection:
  - [ ] explicit `--log-type`
  - [ ] optional `auto`
- [ ] Route each source into its own parser, then normalize output.

### Done when
- [ ] AegisLog can ingest raw logs from more than just SSH and Apache.
- [ ] All supported parsers emit the same normalized event structure.

---

## Phase 3 — Generic CLI path

- [ ] Add a new CLI path for normalized logs.
- [ ] Keep `python -m aegislog.cli` style.
- [ ] Add commands that work on normalized events:
  - [ ] analyze
  - [ ] incidents
  - [ ] explain
- [ ] Allow users to pass their own file without needing SSH/Apache-specific flags.
- [ ] Add an option like:
  - [ ] `--log-type generic`
  - [ ] `--input-format jsonl|text|syslog|auto`

### Done when
- [ ] A user can point AegisLog at their own log file and get useful output.

---

## Phase 4 — Generic event grouping

- [ ] Design generic session/grouping rules.
- [ ] Group by combinations like:
  - [ ] src_ip + time window
  - [ ] user + time window
  - [ ] host + service + time window
  - [ ] session_hint when available
- [ ] Keep SSH-specific grouping logic where it is.
- [ ] Keep Apache-specific grouping logic where it is.
- [ ] Add a generic grouping strategy for unknown logs.

### Done when
- [ ] User logs can still be grouped into incidents even without SSH-specific semantics.

---

## Phase 5 — Generic feature extraction

- [ ] Add source-agnostic features for normalized logs:
  - [ ] event_count
  - [ ] distinct_users
  - [ ] distinct_hosts
  - [ ] distinct_ips
  - [ ] error_ratio
  - [ ] warning_ratio
  - [ ] rare_hour
  - [ ] burst_max_per_minute
  - [ ] status_4xx
  - [ ] status_5xx
  - [ ] failed_action_count
  - [ ] successful_action_count
- [ ] Preserve source-specific features in separate branches.
- [ ] Keep feature naming consistent across log types where possible.

### Done when
- [ ] The anomaly/scoring layer has enough signal to rank generic incidents.

---

## Phase 6 — Generic incident model

- [ ] Keep current incident fields:
  - [ ] severity
  - [ ] confidence
  - [ ] priority
  - [ ] attack_pattern
- [ ] Add generic attack patterns:
  - [ ] auth_fail_burst
  - [ ] error_spike
  - [ ] suspicious_status_spike
  - [ ] rare_hour_activity
  - [ ] unknown_anomalous_behavior
- [ ] Avoid pretending to know more than the source supports.
- [ ] Use “unknown” or “generic” labels when confidence is low.

### Done when
- [ ] AegisLog can label incidents from user logs in a sensible way without overfitting to SSH or Apache terms.

---

## Phase 7 — AI explain for generic logs

- [ ] Add a generic evidence builder for normalized incidents.
- [ ] Add a generic prompt template.
- [ ] Reuse the same `generate_incident_analysis(...)` client.
- [ ] Keep the same output schema:
  - [ ] summary
  - [ ] evidence
  - [ ] hypothesis
  - [ ] caveats
  - [ ] next_steps
  - [ ] playbook_slug
  - [ ] playbook_notes
- [ ] Make prompts describe uncertainty clearly when the log format is only partially understood.

### Done when
- [ ] User logs get useful AI summaries, not SSH- or Apache-specific wording.

---

## Phase 8 — Mapping-based import

- [ ] Add a simple mapping file format later.
- [ ] Let users define how their fields map to the normalized schema.
- [ ] Example:
  - [ ] `client_ip -> src_ip`
  - [ ] `username -> user`
  - [ ] `level -> severity`
  - [ ] `msg -> message`
- [ ] Support a config file such as:
  - [ ] YAML
  - [ ] JSON
- [ ] Keep this as phase 2 of generic-log usability, not phase 1.

### Done when
- [ ] Users can bring custom app logs without code changes.

---

## Phase 9 — Documentation and samples

- [ ] Add sample generic logs under `data/`.
- [ ] Add one JSONL example.
- [ ] Add one syslog-like example.
- [ ] Add one application log example.
- [ ] Update README:
  - [ ] SSH usage
  - [ ] Apache usage
  - [ ] generic usage
  - [ ] Ollama usage
- [ ] Add a “bring your own log” section.

### Done when
- [ ] A new user can try the tool on their own logs with minimal guessing.

---

## Phase 10 — Safety and trust

- [ ] Never claim certainty when the parser confidence is low.
- [ ] Surface parser confidence in generic mode.
- [ ] Keep raw logs available for inspection in outputs.
- [ ] Validate all imported fields before scoring and AI use.
- [ ] Redact or warn on clearly sensitive values later.
- [ ] Make AI explain optional, never mandatory.

### Done when
- [ ] The tool stays honest and safe even on messy user data.

---

## Recommended build order

- [ ] 1. Normalized schema
- [ ] 2. SSH adapter -> normalized events
- [ ] 3. Apache adapter -> normalized events
- [ ] 4. Generic JSONL parser
- [ ] 5. Generic grouping + feature extraction
- [ ] 6. Generic explain path
- [ ] 7. Mapping file support
- [ ] 8. Docs and samples

---

## Product standard

- [ ] AegisLog should become “works on your logs with adapters and normalization”
- [ ] not “works only on the logs the developer hardcoded”