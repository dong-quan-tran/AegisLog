import argparse

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