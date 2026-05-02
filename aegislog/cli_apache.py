import argparse
import sys
from dataclasses import dataclass
from typing import List

import pandas as pd


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

    return ApacheSessionSummary(
        session_id=row["session_id"],
        score=float(row.get("score", 0.0)),
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
        description="Inspect suspicious Apache sessions from features and scores.",
    )
    parser.add_argument(
        "--features-csv",
        required=True,
        help="Path to Apache features CSV (must include a 'score' column).",
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

    try:
        df = pd.read_csv(args.features_csv)
    except Exception as exc:
        print(f"failed to read features CSV: {exc}", file=sys.stderr)
        return 1

    if "score" not in df.columns:
        print("features CSV must contain a 'score' column", file=sys.stderr)
        return 1

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
        print(f"features CSV missing required columns: {', '.join(missing)}", file=sys.stderr)
        return 1

    df_sorted = df.sort_values("score", ascending=False).head(args.top)

    if df_sorted.empty:
        print("no sessions found in features CSV", file=sys.stderr)
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