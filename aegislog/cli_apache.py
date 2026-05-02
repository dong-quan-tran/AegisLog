import argparse
from dataclasses import dataclass
from typing import List

from aegislog.parsing.apache_error import parse_error_file
from aegislog.features.sessions import build_sessions
from aegislog.ml.pipeline import score_sessions
from aegislog.cli_common import resolve_model_path


@dataclass
class ApacheSessionSummary:
    session_id: str
    score: float
    error_ratio: float
    apache_error_vs_notice_ratio: float
    apache_error_burst_max_per_minute: int
    apache_5xx_burst_max_per_minute: int
    apache_rare_error_message_ratio: float
    apache_high_severity_ratio: float
    apache_rare_hour: int
    apache_notes: str


def load_apache_sessions_for_cli(args: argparse.Namespace):
    events = parse_error_file(args.log_path)
    sessions = build_sessions(events)
    model_path = resolve_model_path(args)
    df = score_sessions(sessions, model_path=model_path)
    return sessions, df


def summarize_apache_row(row) -> ApacheSessionSummary:
    notes: list[str] = []

    if row["error_ratio"] > 0.3:
        notes.append("high fraction of 4xx/5xx responses")

    if row["apache_error_vs_notice_ratio"] > 2.0:
        notes.append("errors dominate over notices")

    if row["apache_error_burst_max_per_minute"] >= 10:
        notes.append("error spike within a single minute")

    if row["apache_5xx_burst_max_per_minute"] >= 5:
        notes.append("5xx spike within a single minute")

    if row["apache_rare_error_message_ratio"] > 0.3:
        notes.append("many rare error templates")

    if row["apache_high_severity_ratio"] > 0.1:
        notes.append("non-trivial share of crit/alert/emerg")

    if row["apache_rare_hour"]:
        notes.append("activity during unusual hours")

    notes_text = "; ".join(notes) if notes else "no notable anomalies"

    score = row.get("ensemble_score", row.get("anomaly_score", row.get("score", 0.0)))

    return ApacheSessionSummary(
        session_id=row["session_id"],
        score=float(score),
        error_ratio=float(row["error_ratio"]),
        apache_error_vs_notice_ratio=float(row["apache_error_vs_notice_ratio"]),
        apache_error_burst_max_per_minute=int(row["apache_error_burst_max_per_minute"]),
        apache_5xx_burst_max_per_minute=int(row["apache_5xx_burst_max_per_minute"]),
        apache_rare_error_message_ratio=float(row["apache_rare_error_message_ratio"]),
        apache_high_severity_ratio=float(row["apache_high_severity_ratio"]),
        apache_rare_hour=int(row["apache_rare_hour"]),
        apache_notes=notes_text,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegislog-apache",
        description="Inspect suspicious Apache sessions directly from log files.",
    )
    parser.add_argument(
        "log_path",
        help="Path to Apache error log file.",
    )
    parser.add_argument(
        "--log-type",
        choices=["apache_error"],
        default="apache_error",
        help="Type of log file to parse (currently apache_error only).",
    )
    parser.add_argument(
        "--model-path",
        default=None,
        help="Path to trained model (defaults depend on log-type/model-type).",
    )
    parser.add_argument(
        "--model-type",
        choices=["iforest", "ocsvm", "lof"],
        default="iforest",
        help="Anomaly model to use for scoring.",
    )
    parser.add_argument(
        "-n",
        "--top",
        type=int,
        default=20,
        help="Number of top suspicious sessions to show (default: 20).",
    )
    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    sessions, df = load_apache_sessions_for_cli(args)

    if df.empty:
        print("No sessions found.")
        return 0

    required_cols = [
        "session_id",
        "error_ratio",
        "apache_error_vs_notice_ratio",
        "apache_error_burst_max_per_minute",
        "apache_5xx_burst_max_per_minute",
        "apache_rare_error_message_ratio",
        "apache_high_severity_ratio",
        "apache_rare_hour",
    ]
    missing = [c for c in required_cols if c not in df.columns]
    if missing:
        print(f"scored data missing required columns: {', '.join(missing)}")
        return 1

    score_col = "ensemble_score" if "ensemble_score" in df.columns else "anomaly_score"
    df_sorted = df.sort_values(score_col, ascending=False).head(args.top)

    if df_sorted.empty:
        print("No sessions found.")
        return 0

    print(f"Top {len(df_sorted)} suspicious Apache sessions:\n")

    for _, row in df_sorted.iterrows():
        summary = summarize_apache_row(row)
        print(
            f"{summary.session_id}  "
            f"score={summary.score:.3f}  "
            f"errors={summary.error_ratio:.2f}  "
            f"5xx_burst={summary.apache_5xx_burst_max_per_minute}  "
            f"notes: {summary.apache_notes}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())