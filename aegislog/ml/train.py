import argparse
import joblib
from pathlib import Path

from aegislog.parsing.access import parse_access_file
from aegislog.features.sessions import build_sessions
from aegislog.features.behavioral import sessions_to_features
from aegislog.ml.pipeline import build_pipeline

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--logs-path", required=True, help="Path to access.log")
    parser.add_argument("--model-path", default="models/log_anomaly_iforest.joblib")
    args = parser.parse_args()

    events = parse_access_file(args.logs_path)
    sessions = build_sessions(events)
    df = sessions_to_features(sessions)

    pipeline = build_pipeline()
    pipeline.fit(df)  # unsupervised

    Path(args.model_path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, args.model_path)
    print(f"Saved model to {args.model_path}")

if __name__ == "__main__":
    main()
