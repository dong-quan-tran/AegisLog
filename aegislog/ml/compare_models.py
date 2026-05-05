import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

import numpy as np
import pandas as pd

from aegislog.parsing.apache_error import parse_error_file
from aegislog.parsing.auth_ssh import parse_ssh_file
from aegislog.features.sessions import build_sessions
from aegislog.features.behavioral import sessions_to_features
from aegislog.ml.pipeline import (
    build_pipeline,
    build_ocsvm_pipeline,
    build_lof_pipeline,
    NUMERIC_FEATURES,
)

FEATURE_VERSION = "v3-baseline-deviation"


def _load_events(log_path: str, log_type: str):
    if log_type == "apache_error":
        return parse_error_file(log_path)
    elif log_type == "ssh_auth":
        return parse_ssh_file(log_path)
    else:
        raise ValueError(f"Unsupported log_type: {log_type}")


def _build_model(model_type: str):
    if model_type == "iforest":
        return build_pipeline()
    elif model_type == "ocsvm":
        return build_ocsvm_pipeline()
    elif model_type == "lof":
        return build_lof_pipeline()
    else:
        raise ValueError(f"Unsupported model_type: {model_type}")


def _score_with_model(model, df: pd.DataFrame) -> np.ndarray:
    # All three pipelines expose a .decision_function that we can use consistently.
    scores = model.decision_function(df[NUMERIC_FEATURES])
    # Convention: higher = more anomalous
    return -scores


def _summarize_scores(scores: np.ndarray, threshold_percentile: float = 99.0) -> Dict[str, Any]:
    if scores.size == 0:
        return {
            "score_min": None,
            "score_max": None,
            "score_mean": None,
            "score_p95": None,
            "threshold_percentile": threshold_percentile,
            "threshold_value": None,
            "fraction_above_threshold": None,
        }

    score_min = float(scores.min())
    score_max = float(scores.max())
    score_mean = float(scores.mean())
    score_p95 = float(np.percentile(scores, 95))

    threshold_value = float(np.percentile(scores, threshold_percentile))
    fraction_above = float((scores >= threshold_value).mean())

    return {
        "score_min": score_min,
        "score_max": score_max,
        "score_mean": score_mean,
        "score_p95": score_p95,
        "threshold_percentile": threshold_percentile,
        "threshold_value": threshold_value,
        "fraction_above_threshold": fraction_above,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Compare IF / OCSVM / LOF on the same log and feature set."
    )
    parser.add_argument("log_path", help="Path to log file (SSH or Apache).")
    parser.add_argument(
        "--log-type",
        choices=["ssh_auth", "apache_error"],
        required=True,
        help="Log type to parse.",
    )
    parser.add_argument(
        "--threshold-percentile",
        type=float,
        default=99.0,
        help="Percentile used as anomaly threshold for summary stats.",
    )
    parser.add_argument(
        "--output-json",
        type=str,
        help="Optional path to write JSON summary for this comparison.",
    )
    args = parser.parse_args()

    events = _load_events(args.log_path, args.log_type)
    sessions = build_sessions(events)
    df = sessions_to_features(sessions)

    if df.empty:
        raise RuntimeError("No sessions/features produced from the provided log.")

    model_types = ["iforest", "ocsvm", "lof"]
    summaries: Dict[str, Any] = {}

    print(f"Comparing models on {args.log_path} (log_type={args.log_type})")
    print(f"Feature version: {FEATURE_VERSION}")
    print(f"Total sessions: {len(df)}")

    for model_type in model_types:
        print(f"\n=== {model_type.upper()} ===")
        model = _build_model(model_type)
        scores = _score_with_model(model, df)
        summary = _summarize_scores(scores, threshold_percentile=args.threshold_percentile)
        summaries[model_type] = summary

        print(f"score_min: {summary['score_min']:.4f}")
        print(f"score_max: {summary['score_max']:.4f}")
        print(f"score_mean: {summary['score_mean']:.4f}")
        print(f"score_p95: {summary['score_p95']:.4f}")
        print(f"threshold ({summary['threshold_percentile']}th): {summary['threshold_value']:.4f}")
        print(f"fraction_above_threshold: {summary['fraction_above_threshold']:.4f}")

    # Optionally write JSON summary
    if args.output_json:
        out_path = Path(args.output_json)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "log_type": args.log_type,
            "logs_path": str(Path(args.log_path)),
            "feature_version": FEATURE_VERSION,
            "threshold_percentile": args.threshold_percentile,
            "model_summaries": summaries,
            "compared_at_utc": datetime.now(timezone.utc).isoformat(),
        }
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\nWrote comparison summary to {out_path}")


if __name__ == "__main__":
    main()