Core ingestion
Add field-mapping config format for custom logs.

Add config-driven generic JSONL parser using NormalizedEvent.from_mapping(...).

Add one more input format, ideally RFC 3164 syslog with basic PRI, timestamp, hostname, severity, and message parsing. RFC 3164 defines the PRI and header structure clearly enough for a simple first parser.

Add tests for syslog parsing and normalization edge cases.

CLI integration
Wire --mapping path/to/mapping.yaml into the real normalize command.

Add --mapping support to normalized-incidents.

Add --mapping to normalized-explain if that flow already accepts generic normalized input.

Add end-to-end CLI tests for mapped JSONL and, after it exists, syslog.

Incident flows
Verify generic logs can move cleanly from parse → normalize → group into incidents.

Verify generic-incidents and normalized-incidents work across SSH, Apache, and generic JSONL.

Verify evidence generation and AI explain still behave consistently across source types.

Documentation
Add a README section: Bring your own logs.

Document JSONL normalization with and without mapping files.

Document normalize-ssh and normalize-apache.

Document generic-incidents, normalized-incidents, generic-explain, and normalized-explain.

Document AI setup options, including mock mode and Ollama.

Samples and polish
Add 1–2 sample generic logs, including one that benefits from a mapping file.

Add a short architecture overview covering parsers → adapters → NormalizedEvent → incidents → evidence → AI explain.

Do a final full test run and fix any broken assumptions exposed by the new generic pipeline.

Suggested next order
Wire --mapping into the actual CLI entrypoint.

Add RFC 3164 syslog parser.

Add CLI/integration tests for both.

Update README and add sample files.

Do final polish on incident and AI flows.

That order keeps the project moving through the real user path instead of just building isolated helpers. RFC 3164 is the best next parser because its traditional header structure is standardized enough to keep the scope small.