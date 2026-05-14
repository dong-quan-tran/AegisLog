import argparse
import json

from aegislog.cli_common import write_output, session_row_to_dict
from aegislog.cli_analyze import register_analyze_parser
from aegislog.cli_ssh import (
    incident_to_dict,
    cmd_incidents,
    cmd_explain,
    cmd_report,
    cmd_ai_explain,
    register_incidents_parser,
    register_explain_parser,
    register_report_parser,
    register_ai_explain_parser,
)
from aegislog.parsing.generic import load_generic_jsonl, summarize_normalized_events
from aegislog.incidents_generic import (
    group_generic_events_to_incidents,
    group_generic_events_to_incident_bundles,
    build_generic_incident_evidence,
)
from aegislog.ai.prompts_structured import build_structured_incident_analysis_prompt
from aegislog.ai.client import generate_incident_analysis, LLMError
from aegislog.adapters.ssh import (
    load_ssh_normalized_events,
    summarize_ssh_normalized_events,
)
from aegislog.adapters.apache import (
    load_apache_normalized_events,
    summarize_apache_normalized_events,
)
from aegislog.normalized_loader import load_normalized_events, NormalizedLoadError
from aegislog.incidents_normalized import build_normalized_incident_evidence

__all__ = [
    "write_output",
    "session_row_to_dict",
    "incident_to_dict",
    "build_parser",
    "cmd_examples",
    "cmd_init",
    "cmd_train",
    "cmd_incidents",
    "cmd_explain",
    "cmd_ai_explain",
    "cmd_report",
    "main",
]


def cmd_examples(args: argparse.Namespace) -> None:
    print("Example commands:")
    print("  aegislog analyze data/loghub/SSH.log --log-type ssh_auth --profile ssh")
    print("  aegislog incidents data/loghub/SSH.log --log-type ssh_auth")
    print("  aegislog explain data/loghub/SSH.log --log-type ssh_auth --index 0")
    print("  aegislog normalize data/sample_generic.jsonl")
    print("  aegislog normalize-ssh data/loghub/SSH.log")
    print("  aegislog normalize-apache data/loghub/Apache.log")
    print("  aegislog generic-incidents data/sample_generic.jsonl")
    print("  aegislog generic-explain data/sample_generic.jsonl --index 0 --use-ai")
    print("  aegislog normalized-incidents data/sample_generic.jsonl --source-type generic")
    print("  aegislog normalized-incidents data/loghub/SSH.log --source-type ssh")
    print("  aegislog normalized-incidents data/loghub/Apache.log --source-type apache")
    print("  aegislog normalized-explain data/sample_generic.jsonl --source-type generic --first --use-ai")
    print("  aegislog normalized-explain data/loghub/SSH.log --source-type ssh --index 0 --use-ai")
    print("  aegislog normalized-explain data/loghub/Apache.log --source-type apache --index 0 --use-ai")


def cmd_init(args: argparse.Namespace) -> None:
    print("Init placeholder: will set up SQLite experiment DB.")


def cmd_train(args: argparse.Namespace) -> None:
    from aegislog.ml.train import main as train_main

    train_main()


def cmd_normalize(args: argparse.Namespace) -> int:
    try:
        events, errors = load_normalized_events(
            source_type="generic",
            path=args.path,
            input_format=args.input_format,
        )
    except NormalizedLoadError as e:
        print(str(e))
        return 1
    except Exception as e:
        print(f"Failed to normalize generic log: {e}")
        return 1

    preview = [event.to_dict() for event in events[: args.top]]
    summary = summarize_normalized_events(events)

    payload = {
        "path": args.path,
        "input_format": args.input_format,
        "summary": summary,
        "preview": preview,
        "parse_errors": errors,
    }

    if args.format == "json":
        text = json.dumps(payload, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(text + "\n")
        else:
            print(text)
        return 0

    print(f"Normalized {summary['total_events']} event(s) from {args.path}")
    print(f"Previewing first {len(preview)} event(s)")
    if summary["severity_counts"]:
        print(f"Severity counts: {summary['severity_counts']}")
    if summary["event_category_counts"]:
        print(f"Event category counts: {summary['event_category_counts']}")
    if summary["event_action_counts"]:
        print(f"Event action counts: {summary['event_action_counts']}")

    if errors:
        print(f"Parse errors: {len(errors)}")
        for err in errors[:10]:
            print(f"  {err}")

    for idx, event in enumerate(preview):
        print(f"\n[{idx}]")
        print(json.dumps(event, indent=2))

    return 0


def cmd_normalize_ssh(args: argparse.Namespace) -> int:
    try:
        events, _ = load_normalized_events(
            source_type="ssh",
            path=args.path,
            input_format="jsonl",
        )
    except NormalizedLoadError as e:
        print(str(e))
        return 1
    except Exception as e:
        print(f"Failed to normalize SSH log: {e}")
        return 1

    preview = [event.to_dict() for event in events[: args.top]]
    summary = summarize_ssh_normalized_events(events)

    payload = {
        "path": args.path,
        "source_type": "ssh",
        "summary": summary,
        "preview": preview,
    }

    if args.format == "json":
        text = json.dumps(payload, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(text + "\n")
        else:
            print(text)
        return 0

    print(f"Normalized {summary['total_events']} SSH event(s) from {args.path}")
    print(f"Previewing first {len(preview)} event(s)")
    print(f"Severity counts: {summary['severity_counts']}")
    print(f"Event action counts: {summary['event_action_counts']}")
    print(f"Distinct users: {summary['distinct_users']}")
    print(f"Distinct source IPs: {summary['distinct_src_ips']}")

    for idx, item in enumerate(preview):
        print()
        print(f"[{idx}]")
        print(json.dumps(item, indent=2))

    return 0


def cmd_normalize_apache(args: argparse.Namespace) -> int:
    try:
        events, _ = load_normalized_events(
            source_type="apache",
            path=args.path,
            input_format="jsonl",
        )
    except NormalizedLoadError as e:
        print(str(e))
        return 1
    except Exception as e:
        print(f"Failed to normalize Apache log: {e}")
        return 1

    preview = [event.to_dict() for event in events[: args.top]]
    summary = summarize_apache_normalized_events(events)

    payload = {
        "path": args.path,
        "source_type": "apache",
        "summary": summary,
        "preview": preview,
    }

    if args.format == "json":
        text = json.dumps(payload, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(text + "\n")
        else:
            print(text)
        return 0

    print(f"Normalized {summary['total_events']} Apache event(s) from {args.path}")
    print(f"Previewing first {len(preview)} event(s)")
    print(f"Severity counts: {summary['severity_counts']}")
    print(f"Event action counts: {summary['event_action_counts']}")
    print(f"Apache level counts: {summary['apache_level_counts']}")

    for idx, item in enumerate(preview):
        print()
        print(f"[{idx}]")
        print(json.dumps(item, indent=2))

    return 0


def cmd_generic_incidents(args: argparse.Namespace) -> int:
    try:
        events, errors = load_normalized_events(
            source_type="generic",
            path=args.path,
            input_format=args.input_format,
        )
    except NormalizedLoadError as e:
        print(str(e))
        return 1
    except Exception as e:
        print(f"Failed to group generic incidents: {e}")
        return 1

    incidents = group_generic_events_to_incidents(
        events,
        window_minutes=args.window_minutes,
    )

    payload = {
        "path": args.path,
        "input_format": args.input_format,
        "window_minutes": args.window_minutes,
        "total_events": len(events),
        "total_incidents": len(incidents),
        "incidents": [incident.to_dict() for incident in incidents[: args.top]],
        "parse_errors": errors,
    }

    if args.format == "json":
        text = json.dumps(payload, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(text + "\n")
        else:
            print(text)
        return 0

    print(f"Grouped {len(events)} event(s) into {len(incidents)} generic incident(s)")
    print(f"Showing top {min(len(incidents), args.top)} incident(s)")

    if errors:
        print(f"Parse errors: {len(errors)}")
        for err in errors[:10]:
            print(f"  {err}")

    for idx, incident in enumerate(incidents[: args.top]):
        print(
            f"[{idx}] id={incident.incident_id} "
            f"priority={incident.priority} severity={incident.severity} "
            f"confidence={incident.confidence} pattern={incident.attack_pattern} "
            f"events={incident.event_count} errors={incident.error_count} warnings={incident.warning_count}"
        )
        print(f"  group_key={incident.group_key}")
        print(f"  summary_title={incident.summary_title}")
        print(f"  summary_description={incident.summary_description}")

    return 0


def cmd_normalized_incidents(args: argparse.Namespace) -> int:
    try:
        events, errors = load_normalized_events(
            source_type=args.source_type,
            path=args.path,
            input_format=args.input_format,
        )
    except NormalizedLoadError as e:
        print(str(e))
        return 1
    except Exception as e:
        print(f"Failed to group normalized incidents: {e}")
        return 1

    incidents = group_generic_events_to_incidents(
        events,
        window_minutes=args.window_minutes,
    )

    payload = {
        "path": args.path,
        "source_type": args.source_type,
        "input_format": args.input_format,
        "window_minutes": args.window_minutes,
        "total_events": len(events),
        "total_incidents": len(incidents),
        "incidents": [incident.to_dict() for incident in incidents[: args.top]],
        "parse_errors": errors,
    }

    if args.format == "json":
        text = json.dumps(payload, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(text + "\n")
        else:
            print(text)
        return 0

    print(
        f"Grouped {len(events)} normalized {args.source_type} event(s) into "
        f"{len(incidents)} incident(s)"
    )
    print(f"Showing top {min(len(incidents), args.top)} incident(s)")

    if errors:
        print(f"Parse errors: {len(errors)}")
        for err in errors[:10]:
            print(f"  {err}")

    for idx, incident in enumerate(incidents[: args.top]):
        print(
            f"[{idx}] id={incident.incident_id} "
            f"priority={incident.priority} severity={incident.severity} "
            f"confidence={incident.confidence} pattern={incident.attack_pattern} "
            f"events={incident.event_count} errors={incident.error_count} warnings={incident.warning_count}"
        )
        print(f"  group_key={incident.group_key}")
        print(f"  summary_title={incident.summary_title}")
        print(f"  summary_description={incident.summary_description}")

    return 0


def cmd_generic_explain(args: argparse.Namespace) -> int:
    events, errors = load_generic_jsonl(args.path)
    bundles = group_generic_events_to_incident_bundles(
        events,
        window_minutes=args.window_minutes,
    )

    if not bundles:
        print("No generic incidents found.")
        return 0

    if args.first:
        bundle = bundles[0]
        index = 0
    else:
        if args.index < 0 or args.index >= len(bundles):
            print(
                f"Invalid index {args.index}. There are {len(bundles)} generic incident(s)."
            )
            return 1
        bundle = bundles[args.index]
        index = args.index

    incident = bundle.incident
    evidence = build_generic_incident_evidence(
        incident,
        bundle.events,
        input_format=args.input_format,
        window_minutes=args.window_minutes,
    )

    ai_analysis = None
    if args.use_ai:
        try:
            prompt = build_structured_incident_analysis_prompt(evidence)
            ai_analysis = generate_incident_analysis(prompt)
        except LLMError as e:
            print(f"  [AI analysis unavailable] {e}")

    payload = {
        "path": args.path,
        "input_format": args.input_format,
        "window_minutes": args.window_minutes,
        "selected_index": index,
        "incident": incident.to_dict(),
        "incident_evidence": evidence.to_dict(),
        "parse_errors": errors,
    }
    if ai_analysis is not None:
        payload["ai_analysis"] = ai_analysis

    if args.format == "json":
        write_output(json.dumps(payload, indent=2), getattr(args, "output", None))
        return 0

    print(f"Explaining generic incident at index {index}: {incident.incident_id}")
    print(
        f"  priority={incident.priority} severity={incident.severity} "
        f"confidence={incident.confidence} pattern={incident.attack_pattern} "
        f"events={incident.event_count} errors={incident.error_count} warnings={incident.warning_count}"
    )
    print(f"  group_key={incident.group_key}")
    print(f"  summary_title={incident.summary_title}")
    print(f"  summary_description={incident.summary_description}")

    if errors:
        print(f"  parse_errors={len(errors)}")

    if ai_analysis is not None:
        print("  ai_summary_begin")
        for line in ai_analysis["summary"].splitlines():
            print(f"    {line}")
        print("  ai_summary_end")

        print("  ai_evidence_begin")
        for item in ai_analysis["evidence"]:
            print(f"    - {item}")
        print("  ai_evidence_end")

        print("  ai_hypothesis_begin")
        for line in ai_analysis["hypothesis"].splitlines():
            print(f"    {line}")
        print("  ai_hypothesis_end")

        print("  ai_caveats_begin")
        for item in ai_analysis["caveats"]:
            print(f"    - {item}")
        print("  ai_caveats_end")

        print("  ai_next_steps_begin")
        for item in ai_analysis["next_steps"]:
            print(f"    - {item}")
        print("  ai_next_steps_end")

        if ai_analysis.get("playbook_slug"):
            print(f"  playbook_slug={ai_analysis['playbook_slug']}")
        if ai_analysis.get("playbook_notes"):
            print(f"  playbook_notes={ai_analysis['playbook_notes']}")

    return 0


def cmd_normalized_explain(args: argparse.Namespace) -> int:
    try:
        events, errors = load_normalized_events(
            source_type=args.source_type,
            path=args.path,
            input_format=args.input_format,
        )
    except NormalizedLoadError as e:
        print(str(e))
        return 1

    bundles = group_generic_events_to_incident_bundles(
        events,
        window_minutes=args.window_minutes,
    )

    if not bundles:
        print("No incidents found for the given source_type and input.")
        return 0

    if args.first:
        bundle = bundles[0]
        index = 0
    else:
        if args.index < 0 or args.index >= len(bundles):
            print(
                f"Invalid index {args.index}. There are {len(bundles)} incident(s) "
                f"for source_type={args.source_type}."
            )
            return 1
        bundle = bundles[args.index]
        index = args.index

    incident = bundle.incident
    evidence = build_normalized_incident_evidence(
        source_type=args.source_type,
        input_format=args.input_format,
        window_minutes=args.window_minutes,
        incident=incident,
        events=bundle.events,
    )

    ai_analysis = None
    if args.use_ai:
        try:
            prompt = build_structured_incident_analysis_prompt(evidence)
            ai_analysis = generate_incident_analysis(prompt)
        except LLMError as e:
            print(f"  [AI analysis unavailable] {e}")

    payload = {
        "path": args.path,
        "source_type": args.source_type,
        "input_format": args.input_format,
        "window_minutes": args.window_minutes,
        "selected_index": index,
        "incident": incident.to_dict(),
        "incident_evidence": evidence.to_dict(),
        "parse_errors": errors,
    }
    if ai_analysis is not None:
        payload["ai_analysis"] = ai_analysis

    if args.format == "json":
        write_output(json.dumps(payload, indent=2), getattr(args, "output", None))
        return 0

    print(
        f"Explaining normalized incident at index {index}: {incident.incident_id} "
        f"(source_type={args.source_type})"
    )
    print(
        f"  priority={incident.priority} severity={incident.severity} "
        f"confidence={incident.confidence} pattern={incident.attack_pattern} "
        f"events={incident.event_count} errors={incident.error_count} "
        f"warnings={incident.warning_count}"
    )
    print(f"  group_key={incident.group_key}")
    print(f"  summary_title={incident.summary_title}")
    print(f"  summary_description={incident.summary_description}")

    if errors:
        print(f"  parse_errors={len(errors)}")

    if ai_analysis is not None:
        print("  ai_summary_begin")
        for line in ai_analysis["summary"].splitlines():
            print(f"    {line}")
        print("  ai_summary_end")

        print("  ai_evidence_begin")
        for item in ai_analysis["evidence"]:
            print(f"    - {item}")
        print("  ai_evidence_end")

        print("  ai_hypothesis_begin")
        for line in ai_analysis["hypothesis"].splitlines():
            print(f"    {line}")
        print("  ai_hypothesis_end")

        print("  ai_caveats_begin")
        for item in ai_analysis["caveats"]:
            print(f"    - {item}")
        print("  ai_caveats_end")

        print("  ai_next_steps_begin")
        for item in ai_analysis["next_steps"]:
            print(f"    - {item}")
        print("  ai_next_steps_end")

        if ai_analysis.get("playbook_slug"):
            print(f"  playbook_slug={ai_analysis['playbook_slug']}")
        if ai_analysis.get("playbook_notes"):
            print(f"  playbook_notes={ai_analysis['playbook_notes']}")

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegislog",
        description=(
            "Analyze logs, detect anomalous sessions, group SSH incidents, "
            "and generate incident explanations."
        ),
        epilog=(
            "Examples:\n"
            "  aegislog analyze data/loghub/SSH.log --log-type ssh_auth --top 5\n"
            "  aegislog analyze data/loghub/SSH.log --log-type ssh_auth --format json --output analyze.json\n"
            "  aegislog incidents data/loghub/SSH.log --top 3 --format json --output incidents.json\n"
            "  aegislog explain data/loghub/SSH.log --index 0 --format json --output explain.json\n"
            "  aegislog ai-explain data/loghub/SSH.log --index 0 --format json --output ai-explain.json\n"
            "  aegislog normalize data/sample_generic.jsonl\n"
            "  aegislog normalize-ssh data/loghub/SSH.log\n"
            "  aegislog normalize-apache data/loghub/Apache.log\n"
            "  aegislog generic-incidents data/sample_generic.jsonl\n"
            "  aegislog generic-explain data/sample_generic.jsonl --index 0 --use-ai\n"
            "  aegislog normalized-incidents data/sample_generic.jsonl --source-type generic\n"
            "  aegislog normalized-incidents data/loghub/SSH.log --source-type ssh\n"
            "  aegislog normalized-incidents data/loghub/Apache.log --source-type apache\n"
            "  aegislog normalized-explain data/sample_generic.jsonl --source-type generic --first --use-ai\n"
            "  aegislog normalized-explain data/loghub/SSH.log --source-type ssh --index 0 --use-ai\n"
            "  aegislog normalized-explain data/loghub/Apache.log --source-type apache --index 0 --use-ai\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    p_normalize = subparsers.add_parser(
        "normalize",
        help="Normalize a user-provided generic JSONL log into AegisLog's common event schema.",
    )
    p_normalize.add_argument("path", help="Path to the input log file.")
    p_normalize.add_argument(
        "--input-format",
        choices=["jsonl"],
        default="jsonl",
        help="Input format for generic logs.",
    )
    p_normalize.add_argument(
        "--top",
        type=int,
        default=5,
        help="Number of normalized events to preview.",
    )
    p_normalize.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format.",
    )
    p_normalize.add_argument(
        "--output",
        help="Optional path to write JSON output instead of stdout.",
    )
    p_normalize.set_defaults(func=cmd_normalize)

    p_norm_ssh = subparsers.add_parser(
        "normalize-ssh",
        help="Normalize SSH auth logs into the common event schema.",
    )
    p_norm_ssh.add_argument("path", help="Path to SSH auth log file.")
    p_norm_ssh.add_argument(
        "--top",
        type=int,
        default=5,
        help="Number of normalized events to preview.",
    )
    p_norm_ssh.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format.",
    )
    p_norm_ssh.add_argument(
        "--output",
        help="Optional path to write JSON output instead of stdout.",
    )
    p_norm_ssh.set_defaults(func=cmd_normalize_ssh)

    p_norm_apache = subparsers.add_parser(
        "normalize-apache",
        help="Normalize Apache error logs into the common event schema.",
    )
    p_norm_apache.add_argument("path", help="Path to Apache error log file.")
    p_norm_apache.add_argument(
        "--top",
        type=int,
        default=5,
        help="Number of normalized events to preview.",
    )
    p_norm_apache.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format.",
    )
    p_norm_apache.add_argument(
        "--output",
        help="Optional path to write JSON output instead of stdout.",
    )
    p_norm_apache.set_defaults(func=cmd_normalize_apache)

    p_generic_incidents = subparsers.add_parser(
        "generic-incidents",
        help="Group normalized generic JSONL events into simple generic incidents.",
    )
    p_generic_incidents.add_argument("path", help="Path to the input log file.")
    p_generic_incidents.add_argument(
        "--input-format",
        choices=["jsonl"],
        default="jsonl",
        help="Input format for generic logs.",
    )
    p_generic_incidents.add_argument(
        "--window-minutes",
        type=int,
        default=15,
        help="Time window used to group generic events.",
    )
    p_generic_incidents.add_argument(
        "--top",
        type=int,
        default=5,
        help="Number of incidents to show.",
    )
    p_generic_incidents.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format.",
    )
    p_generic_incidents.add_argument(
        "--output",
        help="Optional path to write JSON output instead of stdout.",
    )
    p_generic_incidents.set_defaults(func=cmd_generic_incidents)

    p_norm_inc = subparsers.add_parser(
        "normalized-incidents",
        help="Group normalized events from generic/ssh/apache into incidents.",
    )
    p_norm_inc.add_argument("path", help="Path to the input log file.")
    p_norm_inc.add_argument(
        "--source-type",
        choices=["generic", "ssh", "apache"],
        required=True,
        help="Logical source type for this log.",
    )
    p_norm_inc.add_argument(
        "--input-format",
        choices=["jsonl"],
        default="jsonl",
        help="Input format for generic logs (ignored for ssh/apache).",
    )
    p_norm_inc.add_argument(
        "--window-minutes",
        type=int,
        default=15,
        help="Time window used to group events.",
    )
    p_norm_inc.add_argument(
        "--top",
        type=int,
        default=5,
        help="Number of incidents to show.",
    )
    p_norm_inc.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format.",
    )
    p_norm_inc.add_argument(
        "--output",
        help="Optional path to write JSON output instead of stdout.",
    )
    p_norm_inc.set_defaults(func=cmd_normalized_incidents)

    p_generic_explain = subparsers.add_parser(
        "generic-explain",
        help="Generate structured explanation for a single generic incident.",
    )
    p_generic_explain.add_argument("path", help="Path to the input log file.")
    p_generic_explain.add_argument(
        "--input-format",
        choices=["jsonl"],
        default="jsonl",
        help="Input format for generic logs.",
    )
    p_generic_explain.add_argument(
        "--window-minutes",
        type=int,
        default=15,
        help="Time window used to group generic events.",
    )
    p_generic_explain.add_argument(
        "--index",
        type=int,
        default=0,
        help="Zero-based index into the grouped generic incidents.",
    )
    p_generic_explain.add_argument(
        "--first",
        action="store_true",
        help="Explain the first generic incident.",
    )
    p_generic_explain.add_argument(
        "--use-ai",
        action="store_true",
        help="Call the configured AI backend for structured analysis.",
    )
    p_generic_explain.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format.",
    )
    p_generic_explain.add_argument(
        "--output",
        help="Optional path to write JSON output instead of stdout.",
    )
    p_generic_explain.set_defaults(func=cmd_generic_explain)

    p_norm_explain = subparsers.add_parser(
        "normalized-explain",
        help="Generate structured explanation for a normalized incident from generic/ssh/apache sources.",
    )
    p_norm_explain.add_argument("path", help="Path to the input log file.")
    p_norm_explain.add_argument(
        "--source-type",
        choices=["generic", "ssh", "apache"],
        required=True,
        help="Logical source type for this log.",
    )
    p_norm_explain.add_argument(
        "--input-format",
        choices=["jsonl"],
        default="jsonl",
        help="Input format for generic logs (ignored for ssh/apache).",
    )
    p_norm_explain.add_argument(
        "--window-minutes",
        type=int,
        default=15,
        help="Time window used to group events.",
    )
    p_norm_explain.add_argument(
        "--index",
        type=int,
        default=0,
        help="Zero-based index into the grouped incidents.",
    )
    p_norm_explain.add_argument(
        "--first",
        action="store_true",
        help="Explain the first incident.",
    )
    p_norm_explain.add_argument(
        "--use-ai",
        action="store_true",
        help="Call the configured AI backend for structured analysis.",
    )
    p_norm_explain.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format.",
    )
    p_norm_explain.add_argument(
        "--output",
        help="Optional path to write JSON output instead of stdout.",
    )
    p_norm_explain.set_defaults(func=cmd_normalized_explain)

    p_examples = subparsers.add_parser(
        "examples",
        help="Show example log_path/log-type/model-path combinations.",
    )
    p_examples.set_defaults(func=cmd_examples)

    p_init = subparsers.add_parser("init", help="Initialize experiment database.")
    p_init.set_defaults(func=cmd_init)

    p_train = subparsers.add_parser("train", help="Train anomaly model on logs.")
    p_train.add_argument("--logs-path", required=True, help="Path to training logs file.")
    p_train.add_argument(
        "--model-path",
        default="models/log_anomaly_iforest.joblib",
        help="Where to save the trained model.",
    )
    p_train.set_defaults(func=cmd_train)

    register_analyze_parser(subparsers)

    register_incidents_parser(subparsers)
    subparsers.choices["incidents"].set_defaults(func=cmd_incidents)

    register_explain_parser(subparsers)
    subparsers.choices["explain"].set_defaults(func=cmd_explain)

    register_ai_explain_parser(subparsers)
    subparsers.choices["ai-explain"].set_defaults(func=cmd_ai_explain)

    register_report_parser(subparsers)
    subparsers.choices["report"].set_defaults(func=cmd_report)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()