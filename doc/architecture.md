# AegisLog Architecture Overview

This document gives a short, practical overview of how AegisLog processes logs from raw input to grouped incidents and AI-assisted explanations.

## Pipeline summary

At a high level, AegisLog follows this flow:

1. Parsers ingest raw logs from source-specific or generic formats.
2. Adapters and loaders convert parsed records into `NormalizedEvent`.
3. Incident grouping logic clusters related events into incidents.
4. Evidence builders turn incidents plus supporting events into structured evidence.
5. AI explain flows optionally generate natural-language analysis from that evidence.

In shorthand:

```text
raw logs
  -> parsers
  -> adapters / normalized loader
  -> NormalizedEvent
  -> incident grouping
  -> incident evidence
  -> AI explain
```

## Parsers

AegisLog currently supports both source-specific and generic parsing paths.

### Source-specific parsing

- SSH authentication logs
- Apache error logs

These paths use source-aware parsing and source-aware summarization / evidence logic.

### Generic parsing

The generic pipeline is designed for “bring your own logs” workflows.

Supported generic input formats:

- JSONL: one JSON object per line
- Syslog-style text: RFC 3164-style messages

Generic logs may optionally use a mapping file to map custom source fields into the normalized schema.

## Adapters and normalized loading

The normalization layer exists to turn different log shapes into a shared internal event model.

Core idea:

- raw records can come from SSH logs, Apache logs, JSONL, or syslog
- the loader resolves the appropriate parser
- parsed records are converted into `NormalizedEvent`

For generic JSONL logs, a mapping file can define how fields like:

- `client_ip -> src_ip`
- `username -> user`
- `hostname -> host`
- `app -> service`
- `status -> status_code`
- `message -> message`

flow into normalized events.

This keeps downstream grouping and explain logic independent of the original log format.

## NormalizedEvent

`NormalizedEvent` is the common event schema used across the generic and normalized flows.

Typical fields include:

- timestamp
- message
- severity
- event category
- event action
- source IP
- destination IP
- user
- host
- service
- status code
- session hint
- raw / source context where needed

The goal is not to perfectly preserve every source-specific nuance in one model, but to preserve enough consistent structure to support grouping, summarization, and explanation across sources.

## Incident grouping

Once events are normalized, AegisLog groups them into incidents.

### SSH incident path

SSH has a more mature source-specific incident pipeline built around anomalous sessions, IP behavior, severity, confidence, and attack pattern logic.

### Generic / normalized incident path

The generic and normalized flows group normalized events using source-agnostic heuristics such as:

- time window proximity
- grouping keys derived from source IP, host, user, or other event hints
- error / warning bursts
- repeated auth failures
- coarse suspicious patterns

This gives AegisLog a common incident path that works even when no source-specific anomaly model exists.

## Incident evidence

After an incident is selected, AegisLog builds structured evidence for it.

Evidence may include:

- event counts
- error and warning totals
- distinct users, hosts, and source IPs
- first and last seen timestamps
- representative example events
- source-specific metrics for SSH or Apache where applicable

This evidence is the bridge between raw detection logic and human-readable explanations.

## AI explain flows

AegisLog supports AI-assisted explain flows on top of structured evidence.

Current explain paths include:

- SSH explain / AI explain
- Apache explain / AI explain
- Generic explain
- Normalized explain across generic, SSH, and Apache sources

The AI layer does not replace parsing, normalization, or incident logic. Instead, it consumes already-structured evidence and produces:

- summary
- evidence bullets
- hypothesis
- caveats
- next steps
- optional playbook hints

This design keeps the system grounded in structured signals even when AI is enabled.

## Design intent

The architecture is intentionally layered:

- parsing handles source syntax
- normalization handles schema consistency
- grouping handles incident logic
- evidence handles investigation context
- AI handles explanation

That separation makes it easier to add new input formats, new mappings, and new source adapters without rewriting the whole pipeline.