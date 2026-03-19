import argparse

from aegislog.parsing.apache_error import parse_error_file
from aegislog.parsing.auth_ssh import parse_ssh_file
from aegislog.features.sessions import build_sessions
from aegislog.ml.pipeline import score_sessions

from aegislog.incidents import group_sessions_by_ip

from aegislog.parsing.auth_ssh import parse_ssh_file
from aegislog.features.sessions import build_sessions
from aegislog.ml.pipeline import score_sessions

def cmd_incidents(args: argparse.Namespace) -> None:
    if args.log_type != "ssh_auth":
        print("Currently, incidents are only implemented for ssh_auth logs.")
        return

    events = parse_ssh_file(args.log_path)
    sessions = build_sessions(events)
    df = score_sessions(sessions, model_path=args.model_path)

    if df.empty:
        print("No sessions found.")
        return

    incidents = group_sessions_by_ip(sessions, df)
    top = incidents[: args.top]

    print(f"Top {len(top)} IP-based incidents:")
    for inc in top:
        print(
            f"- incident_id={inc.incident_id} ip={inc.ip} "
            f"sessions={len(inc.session_ids)} "
            f"total_events={inc.total_events} "
            f"auth_failed={inc.auth_failed} auth_success={inc.auth_success} "
            f"auth_fail_ratio={inc.auth_fail_ratio:.2f} "
            f"avg_anomaly_score={inc.avg_anomaly_score:.3f}"
        )

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

    sessions = build_sessions(events)
    df = score_sessions(sessions, model_path=args.model_path)

    if df.empty:
        print("No sessions found.")
        return

    df_sorted = df.sort_values("anomaly_score", ascending=False)
    top = df_sorted.head(args.top)

    print(f"Top {len(top)} anomalous sessions:")
    for _, row in top.iterrows():
        print(
            f"- session_id={row['session_id']} "
            f"ip={row['ip']} user={row['user']} "
            f"events={row['event_count']} "
            f"error_ratio={row['error_ratio']:.2f} "
            f"anomaly_score={row['anomaly_score']:.3f}"
        )

def main() -> None:
    parser = argparse.ArgumentParser(prog="aegislog")
    subparsers = parser.add_subparsers(dest="command", required=True)

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

    p_analyze = subparsers.add_parser("analyze", help="Analyze logs and detect incidents.")
    p_analyze.add_argument("log_path", help="Path to log file.")
    p_analyze.add_argument(
        "--model-path",
        default="models/log_anomaly_iforest.joblib",
        help="Path to trained model.",
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
    p_analyze.set_defaults(func=cmd_analyze)

    p_incidents = subparsers.add_parser(
        "incidents", help="Group anomalous sessions into simple IP-based incidents."
    )
    p_incidents.add_argument("log_path", help="Path to log file.")
    p_incidents.add_argument(
        "--model-path",
        default="models/log_anomaly_iforest_ssh.joblib",
        help="Path to trained model.",
    )
    p_incidents.add_argument(
        "--log-type",
        choices=["ssh_auth"],
        default="ssh_auth",
        help="Type of log file to parse (currently ssh_auth only).",
    )
    p_incidents.add_argument(
        "--top",
        type=int,
        default=5,
        help="Number of top incidents to print.",
    )
    p_incidents.set_defaults(func=cmd_incidents)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()

