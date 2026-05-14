Updated remaining checklist
Mapping files & more inputs
Design a simple field-mapping config format (YAML/JSON) that lets users map custom fields into the normalized schema (e.g., client_ip -> src_ip, user_name -> user, status -> status_code, log_message -> message).

Implement a config-driven generic parser for structured text (starting with JSONL) that:

Loads a mapping file.

Applies it to each record to feed NormalizedEvent.from_mapping(...).

Add support for at least one additional input format (e.g., syslog-style text) with a simple parser that:

Extracts basic fields (timestamp, severity/level, message, maybe host).

Uses either hardcoded mapping or the same mapping-file format where possible.

Add CLI affordances:

--mapping path/to/mapping.yaml on normalize.

--mapping path/to/mapping.yaml on normalized-incidents (and possibly normalized-explain for generic logs).

Documentation & usability
Update README with a “Bring your own logs” section showing:

How to run normalize on JSONL (with and without mapping files).

How to run normalize-ssh and normalize-apache.

How to run generic-incidents and normalized-incidents for each source type.

How to enable AI (mock vs Ollama) and run generic-explain / normalized-explain.

Add one or two more sample generic logs:

e.g., a small JSONL with mixed auth and app events.

Optionally one that requires a mapping file to look good.

Add a short architecture overview doc/section describing:

Parsers → adapters → NormalizedEvent.

Grouping into incidents.

Incident evidence → AI explain (generic, SSH, Apache, normalized).