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


def cmd_analyze(args) -> None:
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


def register_analyze_parser(subparsers) -> None:
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