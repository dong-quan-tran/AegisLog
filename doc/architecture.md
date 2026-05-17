# AegisLog Architecture Overview

This document describes how AegisLog processes logs from raw input to grouped incidents and structured explain output across the CLI and HTTP API.

## System summary

AegisLog is organized as a layered log-analysis pipeline:

1. Parsers ingest raw logs from source-specific or generic formats.
2. Loaders and adapters convert parsed records into a shared `NormalizedEvent` model.
3. Incident grouping logic clusters related events into incidents.
4. Evidence builders turn incidents and supporting events into structured investigation context.
5. Optional AI explain flows generate analyst-friendly summaries from structured evidence.

In shorthand:

```text
raw logs
  -> parsers
  -> loaders / adapters
  -> NormalizedEvent
  -> incident grouping
  -> incident evidence
  -> optional AI explain
```

## Supported input paths

AegisLog supports both source-specific and generic ingestion.

### Source-specific inputs

- SSH authentication logs
- Apache error logs

These paths use source-aware parsing, source-aware summarization, and source-aware evidence logic.

### Generic inputs

The generic pipeline is designed for bring-your-own-log workflows.

Supported generic input formats:

- JSONL: one JSON object per line
- Syslog-style text: RFC 3164-style messages

Generic logs may optionally include a mapping configuration so custom source fields can be normalized into the shared schema.

## Core layers

### Parsing layer

The parsing layer handles source syntax.

Responsibilities:
- Read raw files or raw text input.
- Parse JSONL records or syslog messages.
- Extract coarse source fields from source-specific logs.
- Preserve raw context where useful.

Generic syslog parsing currently supports RFC 3164-style timestamps, hostnames, message bodies, and common `service[pid]: message` patterns.

### Mapping layer

The mapping layer lets generic logs describe how source fields map into the normalized schema.

Canonical mapping structure:

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
defaults:
  event_category: auth
```

Behavior:
- `fields` maps normalized field names to one or more source aliases.
- `defaults` injects fallback values when the source record does not provide them.
- `source_type` may override the normalized source label for generic inputs.
- Mapping files may be JSON or YAML.
- Internally, mappings are normalized into a canonical shape where aliases are stored as lists.

The mapping layer exists only for `source_type="generic"`.

### Normalization layer

The normalization layer converts different parsed records into a shared internal model: `NormalizedEvent`.

Typical normalized fields include:

- `timestamp`
- `source_type`
- `raw_message`
- `event_category`
- `event_action`
- `severity`
- `src_ip`
- `dst_ip`
- `user`
- `host`
- `service`
- `status_code`
- `message`
- `session_hint`
- `extra`

Design goals:
- Preserve a stable downstream schema.
- Keep the most useful investigation fields in canonical positions.
- Preserve unmapped or source-specific fields in `extra`.

This allows grouping, summarization, and explain logic to remain mostly independent of original source format.

### Incident grouping layer

Once events are normalized, AegisLog groups them into incidents.

#### Source-specific path

SSH has a more mature source-specific incident path built around anomalous sessions, attack patterns, severity, and confidence logic.

Apache also has source-aware parsing and evidence support.

#### Generic / normalized path

The generic and normalized incident paths operate on `NormalizedEvent` objects using source-agnostic heuristics such as:

- time-window proximity
- grouping keys derived from source IP, host, user, or session hints
- error and warning bursts
- repeated auth failures
- coarse suspicious activity patterns

This design allows incident grouping even when no specialized anomaly model exists for a source.

### Evidence layer

After an incident is selected, AegisLog builds structured evidence for it.

Evidence may include:
- event counts
- warning and error totals
- distinct users, hosts, and source IPs
- first-seen and last-seen timestamps
- representative sample events
- source-specific summary metrics when applicable

This layer is the bridge between machine grouping logic and human-readable explain output.

### AI explain layer

AegisLog supports optional AI-assisted explain flows on top of structured evidence.

Current explain paths include:
- SSH explain / AI explain
- Apache explain / AI explain
- Generic explain
- Normalized explain across generic, SSH, and Apache inputs

The AI layer does not perform parsing or detection. It consumes structured evidence and produces:
- summary
- evidence bullets
- hypothesis
- caveats
- next steps
- optional playbook hints

This design keeps AI grounded in structured evidence rather than raw logs alone.

## Interfaces

AegisLog exposes the same backend capabilities through both a CLI and an HTTP API.

### CLI

The CLI supports:
- normalization
- generic incidents
- normalized incidents
- generic explain
- normalized explain
- existing SSH and Apache explain/report flows

The CLI is intended for local analysis, scripting, and development workflows.

### HTTP API

The FastAPI layer exposes:
- `GET /health`
- `POST /normalize`
- `POST /generic-incidents`
- `POST /normalized-incidents`
- `POST /generic-explain`
- `POST /normalized-explain`

Request models enforce:
- `source_type` in `generic | ssh | apache`
- `input_format` in `jsonl | syslog`
- `mapping` allowed only for `source_type="generic"`
- `content` must not be empty
- unknown request fields are rejected

The API is intended to support the React frontend and other programmatic clients.

### Service layer

Between the API routes and the domain logic, AegisLog uses a small service layer (`services_api.py`).

Responsibilities:
- accept raw log text content
- write temporary files when parsers require file-style input
- call loaders and incident logic
- shape consistent response payloads
- attach optional AI analysis
- clean up temporary artifacts

This layer keeps the FastAPI routes thin and keeps business logic reusable.

## Request and data flow

### Normalize flow

```text
raw content
  -> source_type + input_format selection
  -> parser / loader
  -> NormalizedEvent[]
  -> summary + preview
```

### Incidents flow

```text
NormalizedEvent[]
  -> incident grouping
  -> incident list
```

### Explain flow

```text
NormalizedEvent[]
  -> incident grouping
  -> selected incident
  -> evidence builder
  -> optional AI analysis
  -> structured response
```

## Design intent

The architecture is intentionally layered:

- parsing handles source syntax
- mapping handles source-to-schema adaptation
- normalization handles schema consistency
- grouping handles incident logic
- evidence handles investigation context
- AI handles explanation

This separation makes it easier to:
- add new input formats
- add new source adapters
- expand mapping behavior
- keep API and CLI outputs aligned
- improve explain quality without changing detection logic

## Current status

At the current stage of the project, the backend supports:
- generic JSONL normalization
- generic syslog normalization
- structured field mappings
- incident grouping for generic and normalized flows
- explain flows with optional AI analysis
- FastAPI endpoints aligned with CLI behavior
- automated test coverage across the implemented backend paths