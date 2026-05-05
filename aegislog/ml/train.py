import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib

from aegislog.parsing.apache_error import parse_error_file
from aegislog.parsing.auth_ssh import parse_ssh_file
from aegislog.features.sessions import build_sessions
from aegislog.features.behavioral import sessions_to_features
from aegislog.ml.pipeline import (
    build_pipeline,
    build_ocsvm_pipeline,
    build_lof_pipeline,
    MODEL_PATH,
    NUMERIC_FEATURES,
)

FEATURE_VERSION = "v3-baseline-deviation"
DEFAULT_THRESHOLD_PERCENTILE = 99.0


def _metadata_path_for_model(model_path: str) -> Path:
    model_file = Path(model_path)
    return model_file.with_suffix(".metadata.json")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--logs-path", required=True, help="Path to log file")
    parser.add_argument(
        "--model-path",
        default=MODEL_PATH,
        help="Where to save the trained model.",
    )
    parser.add_argument(
        "--model-type",
        choices=["iforest", "ocsvm", "lof"],
        default="iforest",
        help="Type of model to train.",
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

    if args.model_type == "iforest":
        pipeline = build_pipeline()
    elif args.model_type == "ocsvm":
        pipeline = build_ocsvm_pipeline()
    else:  # "lof"
        pipeline = build_lof_pipeline()

    pipeline.fit(df[NUMERIC_FEATURES])

    model_path = Path(args.model_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, model_path)

    metadata = {
        "log_type": args.log_type,
        "model_type": args.model_type,
        "model_path": str(model_path),
        "logs_path": str(Path(args.logs_path)),
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
        "feature_version": FEATURE_VERSION,
        "numeric_features": list(NUMERIC_FEATURES),
        "session_count": int(len(df)),
        "event_count_total": int(df["event_count"].sum()) if "event_count" in df.columns else None,
        "threshold_percentile_default": DEFAULT_THRESHOLD_PERCENTILE,
    }

    metadata_path = _metadata_path_for_model(str(model_path))
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print(f"Saved model to {model_path}")
    print(f"Saved metadata to {metadata_path}")


if __name__ == "__main__":
    main()