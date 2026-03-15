import argparse

def cmd_init(args: argparse.Namespace) -> None:
    print("Init placeholder: will set up SQLite experiment DB.")

def cmd_train(args: argparse.Namespace) -> None:
    print(f"Train placeholder: will train model from logs at {args.logs_path}.")

def cmd_analyze(args: argparse.Namespace) -> None:
    print(f"Analyze placeholder: will detect incidents in {args.log_path}.")

def main() -> None:
    parser = argparse.ArgumentParser(prog="aegislog")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_init = subparsers.add_parser("init", help="Initialize experiment database.")
    p_init.set_defaults(func=cmd_init)

    p_train = subparsers.add_parser("train", help="Train anomaly model on logs.")
    p_train.add_argument("--logs-path", required=True, help="Path to training logs directory.")
    p_train.set_defaults(func=cmd_train)

    p_analyze = subparsers.add_parser("analyze", help="Analyze logs and detect incidents.")
    p_analyze.add_argument("log_path", help="Path to log file.")
    p_analyze.set_defaults(func=cmd_analyze)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
