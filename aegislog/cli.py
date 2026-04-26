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
    write_output,
    session_row_to_dict,
    resolve_model_path,
    resolve_multi_model_paths,
)

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

__all__ = [
    "write_output",
    "session_row_to_dict",
    "incident_to_dict",
    "build_parser",
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

    register_analyze_parser(subparsers)
    subparsers.choices["analyze"].set_defaults(func=cmd_analyze)

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