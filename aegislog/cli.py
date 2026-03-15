import argparse

from aegislog.parsing.apache_error import parse_error_file
from aegislog.features.sessions import build_sessions
from aegislog.ml.pipeline import score_sessions

def cmd_init(args: argparse.Namespace) -> None:
    print("Init placeholder: will set up SQLite experiment DB.")

def cmd_train(args: argparse.Namespace) -> None:
    from aegislog.ml.train import main as train_main
    train_main()

def cmd_analyze(args: argparse.Namespace) -> None:
    events = parse_error_file(args.log_path)
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
        "--top",
        type=int,
        default=5,
        help="Number of most anomalous sessions to print.",
    )
    p_analyze.set_defaults(func=cmd_analyze)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()

