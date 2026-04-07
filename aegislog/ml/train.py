import argparse
import joblib
from pathlib import Path

from aegislog.parsing.apache_error import parse_error_file
from aegislog.parsing.auth_ssh import parse_ssh_file
from aegislog.features.sessions import build_sessions
from aegislog.features.behavioral import sessions_to_features
from aegislog.ml.pipeline import build_pipeline, MODEL_PATH, NUMERIC_FEATURES


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--logs-path", required=True, help="Path to log file")
    parser.add_argument(
        "--model-path",
        default=MODEL_PATH,
        help="Where to save the trained model.",
    )
    parser.add_argument(
        "--log-type",
        choices=["apache_error", "ssh_auth"],
        default="apache_error",
        help="Type of log file to parse.",
    )
    args = parser.parse_args()

    if args.log_type == "apache_error":
        events = parse_error_file(args.logs_path)
    else:
        events = parse_ssh_file(args.logs_path)

    sessions = build_sessions(events)
    df = sessions_to_features(sessions)

    if df.empty:
        raise RuntimeError("No training data was produced from the provided logs.")

    pipeline = build_pipeline()
    pipeline.fit(df[NUMERIC_FEATURES])

    Path(args.model_path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, args.model_path)
    print(f"Saved model to {args.model_path}")


if __name__ == "__main__":
    main()