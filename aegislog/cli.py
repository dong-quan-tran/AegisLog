import argparse
import json

from aegislog.parsing.apache_error import parse_error_file
from aegislog.parsing.auth_ssh import parse_ssh_file
from aegislog.features.sessions import build_sessions

from aegislog.ml.pipeline import (
    score_sessions,
    score_sessions_multi,
    add_threshold_columns,
)

from aegislog.cli_common import (
    add_json_output_args,
    write_output,
    session_row_to_dict,
    resolve_model_path,
    resolve_multi_model_paths,
)

from aegislog.cli_ssh import (
    add_ssh_source_args,
    add_incident_filter_args,
    incident_to_dict,
    cmd_incidents,
    cmd_explain,
    cmd_report,
)

__all__ = [
    "write_output",
    "session_row_to_dict",
    "incident_to_dict",
    "cmd_analyze",
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


def cmd_analyze(args: argparse.Namespace) -> None:
    if args.log_type == "apache_error":
        events = parse_error_file(args.log_path)
    else:
        events = parse_ssh_file(args.log_path)

    if getattr(args, "profile", None) == "apache":
        args.log_type = "apache_error"
        if args.model_path is None:
            args.model_path = "models/log_anomaly_iforest_apache.joblib"
    elif getattr(args, "profile", None) == "ssh":
        args.log_type = "ssh_auth"
        if args.model_path is None:
            args.model_path = "models/log_anomaly_iforest_ssh.joblib"

    sessions = build_sessions(events)

    if getattr(args, "multi_score", False):
        model_paths = resolve_multi_model_paths(args)
        df = score_sessions_multi(sessions, model_paths=model_paths, add_ensemble=True)
    else:
        model_path = resolve_model_path(args)
        df = score_sessions(sessions, model_path=model_path)

    if df.empty:
        print("No sessions found.")
        return

    sort_col = "ensemble_score" if "ensemble_score" in df.columns else "anomaly_score"
    df = add_threshold_columns(
        df,
        score_col=sort_col,
        threshold_percentile=args.threshold_percentile,
    )

    if getattr(args, "alerts_only", False):
        df = df[df["is_anomalous"]]

    df_sorted = df.sort_values(sort_col, ascending=False)
    top = df_sorted.head(args.top)

    if getattr(args, "format", "text") == "json":
        payload = [session_row_to_dict(row) for _, row in top.iterrows()]
        data = json.dumps(payload, indent=2)
        write_output(data, getattr(args, "output", None))
        return

    print(f"Top {len(top)} anomalous sessions:")
    for _, row in top.iterrows():
        parts = [
            f"session_id={row['session_id']}",
            f"ip={row['ip']}",
            f"user={row['user']}",
            f"events={row['event_count']}",
            f"error_ratio={row['error_ratio']:.2f}",
            f"anomaly_score={row['anomaly_score']:.3f}",
            f"anomaly_percentile={row['anomaly_percentile']:.1f}",
            f"is_anomalous={bool(row['is_anomalous'])}",
        ]

        if "iforest_score" in row.index:
            parts.append(f"iforest_score={row['iforest_score']:.3f}")
        if "ocsvm_score" in row.index:
            parts.append(f"ocsvm_score={row['ocsvm_score']:.3f}")
        if "lof_score" in row.index:
            parts.append(f"lof_score={row['lof_score']:.3f}")
        if "ensemble_score" in row.index:
            parts.append(f"ensemble_score={row['ensemble_score']:.3f}")

        print("- " + " ".join(parts))


def main(argv: list[str] | None = None) -> None:
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
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_examples = subparsers.add_parser(
        "examples", help="Show example log_path/log-type/model-path combinations."
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

    p_analyze = subparsers.add_parser(
        "analyze", help="Analyze logs and print top anomalous sessions."
    )
    p_analyze.add_argument("log_path", help="Path to log file.")
    p_analyze.add_argument(
        "--model-path",
        default=None,
        help="Path to trained model (defaults depend on log-type/profile).",
    )
    p_analyze.add_argument(
        "--log-type",
        choices=["apache_error", "ssh_auth"],
        default="apache_error",
        help="Type of log file to parse.",
    )
    p_analyze.add_argument(
        "--top",
        type=int,
        default=5,
        help="Number of most anomalous sessions to print.",
    )
    add_json_output_args(p_analyze, "analysis results")
    p_analyze.add_argument(
        "--profile",
        choices=["apache", "ssh"],
        help="Shortcut to set common log-type/model-path combos (apache, ssh).",
    )
    p_analyze.add_argument(
        "--model-type",
        choices=["iforest", "ocsvm", "lof"],
        default="iforest",
        help="Anomaly model to use for scoring.",
    )
    p_analyze.add_argument(
        "--multi-score",
        action="store_true",
        help="Score sessions with all available models and include normalized/ensemble scores.",
    )
    p_analyze.add_argument(
        "--threshold-percentile",
        type=float,
        default=99.0,
        help="Percentile threshold for flagging anomalous sessions (default: 99.0).",
    )
    p_analyze.add_argument(
        "--alerts-only",
        action="store_true",
        help="Show only sessions at or above the anomaly threshold.",
    )
    p_analyze.set_defaults(func=cmd_analyze)

    p_incidents = subparsers.add_parser(
        "incidents", help="Group anomalous sessions into simple IP-based incidents."
    )
    add_ssh_source_args(p_incidents)
    add_json_output_args(p_incidents, "incidents")
    p_incidents.add_argument(
        "--show-local-explanation",
        action="store_true",
        help="Show a simple, built-in AI-style explanation for each incident.",
    )
    p_incidents.add_argument(
        "--top",
        type=int,
        default=5,
        help="Number of top incidents to print.",
    )
    p_incidents.add_argument(
        "--print-llm-prompt",
        action="store_true",
        help="For each incident, print a ready-to-send LLM explanation prompt.",
    )
    p_incidents.add_argument(
        "--threshold-percentile",
        type=float,
        default=99.0,
        help="Percentile threshold for flagging anomalous sessions before grouping incidents (default: 99.0).",
    )
    p_incidents.add_argument(
        "--alerts-only",
        action="store_true",
        help="Group incidents from only threshold-flagged anomalous sessions.",
    )
    p_incidents.add_argument(
        "--show-timeline",
        action="store_true",
        help="Show a per-incident session timeline ordered by time.",
    )
    p_incidents.add_argument(
        "--sort-by",
        choices=["severity", "avg_score", "auth_fail_ratio", "total_events"],
        default="severity",
        help="Sort incidents before applying --top (default: severity).",
    )
    add_incident_filter_args(
        p_incidents,
        severity_help="Only include incidents at or above this severity.",
        confidence_help="Only include incidents at or above this confidence level.",
        pattern_help=(
            "Filter incidents by attack pattern; can be specified multiple "
            "times (e.g. --pattern brute_force --pattern password_spray)."
        ),
    )
    p_incidents.set_defaults(func=cmd_incidents)

    p_explain = subparsers.add_parser(
        "explain", help="Explain a single SSH incident with AI-style output."
    )
    add_ssh_source_args(p_explain)
    add_json_output_args(p_explain, "the explanation")
    p_explain.add_argument(
        "--index",
        type=int,
        default=0,
        help="Zero-based index into the sorted list of incidents to explain.",
    )
    p_explain.add_argument(
        "--use-llm",
        action="store_true",
        help=(
            "If set, call a real LLM to generate an incident explanation "
            "(requires OPENAI_API_KEY)."
        ),
    )
    p_explain.add_argument(
        "--threshold-percentile",
        type=float,
        default=99.0,
        help=(
            "Percentile threshold for flagging anomalous sessions before "
            "grouping incidents for explanation (default: 99.0)."
        ),
    )
    p_explain.add_argument(
        "--alerts-only",
        action="store_true",
        help="Only explain incidents built from threshold-flagged anomalous sessions.",
    )
    p_explain.add_argument(
        "--first",
        action="store_true",
        help="Explain the first incident after applying any severity/confidence/pattern filters.",
    )
    add_incident_filter_args(
        p_explain,
        severity_help=(
            "Only consider incidents at or above this severity when "
            "selecting by index."
        ),
        confidence_help=(
            "Only consider incidents at or above this confidence when "
            "selecting by index."
        ),
        pattern_help=(
            "Only consider incidents whose attack_pattern matches one of the "
            "given values; can be specified multiple times."
        ),
    )
    p_explain.set_defaults(func=cmd_explain)

    p_report = subparsers.add_parser(
        "report",
        help="Summarize anomalous sessions and grouped incidents with aggregate metrics.",
    )
    add_ssh_source_args(p_report)
    add_json_output_args(p_report, "the report")
    p_report.add_argument(
        "--multi-score",
        action="store_true",
        help="Score sessions with all available models and include normalized/ensemble scores.",
    )
    p_report.add_argument(
        "--threshold-percentile",
        type=float,
        default=99.0,
        help="Percentile threshold for flagging anomalous sessions before reporting (default: 99.0).",
    )
    p_report.add_argument(
        "--top",
        type=int,
        default=5,
        help="Number of top IPs/users to include in the report.",
    )
    p_report.add_argument(
        "--alerts-only",
        action="store_true",
        help="Build the report from only threshold-flagged anomalous sessions.",
    )
    add_incident_filter_args(
        p_report,
        severity_help="Only include incidents at or above this severity in the report.",
        confidence_help=(
            "Only include incidents at or above this confidence level in the report."
        ),
        pattern_help=(
            "Only include incidents whose attack_pattern matches one of the "
            "given values in the report; can be specified multiple times."
        ),
    )
    p_report.set_defaults(func=cmd_report)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()