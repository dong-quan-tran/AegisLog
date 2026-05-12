Remaining checklist (from here forward)
Adapters / normalization polish
Clean up Apache error parser so log level is a first-class field, not stashed in user_agent, and adjust the adapter accordingly.

Add small, user-friendly error handling for all normalize / normalized-incidents commands (e.g., missing file, unsupported source type) so users don’t see raw tracebacks.

Add one or two tiny unit-style tests for each adapter (SSH/Apache) that assert a couple of representative lines normalize into the expected NormalizedEvent fields (timestamp, source_type, event_action, severity, session_hint, extra).

Normalized explain (AI on generic/SSH/Apache)
Design a generic incident evidence dataclass/type that can describe any normalized incident (generic/SSH/Apache) using only normalized fields (no source-specific types).

Add a normalized incident explain CLI (either normalized-explain or an extension of generic-explain) that:

Accepts --source-type (generic, ssh, apache) and --window-minutes.

Uses load_normalized_events(...) + group_generic_events_to_incident_bundles(...).

Selects an incident by --index or --first.

Builds generic incident evidence from the normalized events + incident.

Add a prompt builder for generic/normalized incidents that:

Describes uncertainty and the fact that it’s working from a normalized schema.

Uses only normalized fields (no SSH/Apache-specific jargon).

Wire the normalized explain CLI into the existing AI backend layer, reusing:

Existing environment variables (AEGISLOG_AI_BACKEND, AEGISLOG_OLLAMA_MODEL, etc.).

Existing structured response schema (summary, evidence, hypothesis, caveats, next_steps, playbook_slug, playbook_notes).

Existing failure-handling pattern (friendly “AI unavailable” messages, no stack traces).

Mapping files & more inputs (next phase)
Design a simple field-mapping config format (YAML/JSON) that lets users map custom fields (e.g., client_ip → src_ip, severity → severity, user → user, etc.) into the normalized schema.

Implement a config-driven generic parser for structured text (e.g., JSONL with arbitrary field names), using the mapping file to feed NormalizedEvent.from_mapping(...).

Add support for at least one additional input format (e.g., syslog-style text) with a simple generic parser and mapping into NormalizedEvent.

Add small CLI affordances for those mappings, e.g. --mapping path/to/mapping.yaml on normalize / normalized-incidents.

Documentation & usability
Update README with a “Bring your own logs” section showing:

How to run normalize on JSONL.

How to run normalize-ssh and normalize-apache.

How to run normalized-incidents for each source type.

How to enable AI (mock vs Ollama) and run the explain commands.

Add one or two more sample logs (e.g., another small JSONL with mixed auth/app events) for quick demos.

Add a short “architecture overview” doc or section explaining: parsers → adapters → normalized events → grouping → AI explain.

