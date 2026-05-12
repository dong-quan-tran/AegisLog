import argparse
import json

from aegislog.cli_common import write_output, session_row_to_dict
from aegislog.cli_analyze import register_analyze_parser
from aegislog.cli_ssh import (
    incident_to_dict,
    cmd_incidents,
    cmd_explain,
    cmd_report,
    register_incidents_parser,
    register_explain_parser,
    register_report_parser,
)
from aegislog.parsing.generic import load_generic_jsonl, summarize_normalized_events


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
    "cmd_report",
    "main",
]


def cmd_examples(args: argparse.Namespace) -> None:
    print("Example commands:")
    print("  aegislog analyze data/loghub/SSH.log --log-type ssh_auth --profile ssh")
    print("  aegislog incidents data/loghub/SSH.log --log-type ssh_auth")
    print("  aegislog explain data/loghub/SSH.log --log-type ssh_auth --index 0")


def cmd_init(args: argparse.Namespace) -> None:
    print("Init placeholder: will set up SQLite experiment DB.")


def cmd_train(args: argparse.Namespace) -> None:
    from aegislog.ml.train import main as train_main

    train_main()


def cmd_normalize(args: argparse.Namespace) -> int:
    events, errors = load_generic_jsonl(args.path)

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
            "  aegislog normalize data/sample_generic.jsonl\n"
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

    register_report_parser(subparsers)
    subparsers.choices["report"].set_defaults(func=cmd_report)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()