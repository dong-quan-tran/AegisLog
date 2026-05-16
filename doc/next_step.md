Core ingestion & normalization
Design simple field-mapping config format (YAML) for custom fields → normalized schema.

Implement config-driven generic JSONL parser:

Loads mapping file.

Applies mapping and feeds NormalizedEvent.from_mapping(...).

Add support for additional input format:

RFC3164-style syslog text parser (generic_syslog).

Wire --input-format syslog for source_type=generic in the normalized loader.

CLI affordances
normalize supports:

JSONL (default).

--mapping path/to/mapping.yaml.

--input-format syslog for generic source.

generic-incidents supports:

JSONL and syslog inputs.

Optional --mapping for JSONL.

generic-explain supports:

JSONL and syslog.

--mapping for JSONL.

Optional --use-ai.

normalized-incidents supports:

--source-type generic|ssh|apache.

--input-format jsonl|syslog for generic.

Optional --mapping for generic JSONL.

normalized-explain supports:

Same source types and formats as normalized-incidents.

Optional --mapping and --use-ai.

Documentation & samples
“Bring your own logs” doc section:

How to run normalize on JSONL (with/without mapping).

How to run normalize on syslog with --input-format syslog.

SSH / Apache flows:

How to run normalize-ssh and normalize-apache or their equivalents.

How to run generic-incidents / normalized-incidents for SSH and Apache.

AI enablement docs:

How to enable mock vs Ollama.

How to run generic-explain / normalized-explain with --use-ai.

Sample logs:

data/sample_generic.jsonl (mixed auth/app/web).

data/sample_syslog.log (auth/app/gateway/kernel syslog).

Example mapping file mapping/example_auth_app.yaml.

Architecture overview:

docs/architecture.md with:

Parsers → adapters → NormalizedEvent.

Grouping into incidents.

Incident evidence → AI explain (generic, SSH, Apache, normalized).

Quality & polish
End-to-end smoke tests for:

normalize (JSONL, JSONL+mapping, syslog).

generic-incidents (JSONL, JSONL+mapping, syslog).

generic-explain (JSONL, JSONL+mapping+AI, syslog).

normalized-incidents (generic JSONL, generic syslog, SSH, Apache).

normalized-explain (generic JSONL, generic syslog, SSH, Apache).

Mapping loader and parser behavior aligned well enough for this cut (no fatal errors with the current mapping file).

Commit history:

One commit for generic syslog support + mapping/loader changes.

One commit for architecture doc + syslog sample log.

Deferred to tomorrow / future iterations
Generic HTTP ingestion endpoint / tiny web UI for JSONL/syslog.

SQLite incident store (schema + writes).

Triage loop CLI / UI:

Mark incidents as true_incident, benign, needs_review.

Richer syslog message parsing:

Extract IP, user, status, and session hints from message body where obvious.

Tests specifically for syslog parsing edge cases (missing PRI, weird timestamps, etc.).