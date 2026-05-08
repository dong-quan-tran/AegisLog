import argparse
import json
from dataclasses import dataclass, asdict
from typing import List

from aegislog.ai.client import generate_incident_analysis
from aegislog.parsing.apache_error import parse_error_file
from aegislog.features.sessions import build_sessions
from aegislog.ml.pipeline import score_sessions
from aegislog.cli_common import resolve_model_path, add_json_output_args, write_output
from aegislog.incidents import build_apache_incident_evidence
from aegislog.features.sessions import Session


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


def _ensure_required_columns(df):
    required_cols = [
        "session_id",
        "error_ratio",
        "apache_error_vs_notice_ratio",
        "apache_error_burst_max_per_minute",
        "apache_5xx_burst_max_per_minute",
        "apache_rare_error_message_ratio",
        "apache_high_severity_ratio",
        "apache_rare_hour",
        "error_events",
    ]
    missing = [c for c in required_cols if c not in df.columns]
    return missing


def _score_column(df) -> str:
    return "ensemble_score" if "ensemble_score" in df.columns else "anomaly_score"


def _apply_apache_filters(df, args: argparse.Namespace):
    if df.empty:
        return df

    filtered = df.copy()
    score_col = _score_column(filtered)

    if getattr(args, "min_score", None) is not None:
        filtered = filtered[filtered[score_col] >= args.min_score]

    if getattr(args, "rare_hour_only", False):
        filtered = filtered[filtered["apache_rare_hour"] > 0]

    if getattr(args, "min_5xx_burst", None) is not None:
        filtered = filtered[filtered["apache_5xx_burst_max_per_minute"] >= args.min_5xx_burst]

    if getattr(args, "min_error_events", None) is not None:
        filtered = filtered[filtered["error_events"] >= args.min_error_events]

    return filtered


def _sorted_apache_df(df, top: int):
    score_col = _score_column(df)
    return df.sort_values(score_col, ascending=False).head(top)


def _find_session_by_id(sessions: List[Session], session_id: str) -> Session | None:
    for s in sessions:
        if s.session_id == session_id:
            return s
    return None


def _build_apache_report_payload(df_sorted) -> dict:
    score_col = _score_column(df_sorted)

    top_session_ids = (
        df_sorted.sort_values(score_col, ascending=False)["session_id"].head(5).tolist()
    )

    payload = {
        "total_sessions_considered": int(len(df_sorted)),
        "rare_hour_sessions": int((df_sorted["apache_rare_hour"] > 0).sum()),
        "sessions_with_5xx_burst": int((df_sorted["apache_5xx_burst_max_per_minute"] >= 5).sum()),
        "sessions_with_error_burst": int((df_sorted["apache_error_burst_max_per_minute"] >= 10).sum()),
        "sessions_with_rare_templates": int((df_sorted["apache_rare_error_message_ratio"] > 0.3).sum()),
        "sessions_with_high_severity_ratio": int((df_sorted["apache_high_severity_ratio"] > 0.1).sum()),
        "sessions_with_error_dominance": int((df_sorted["apache_error_vs_notice_ratio"] > 2.0).sum()),
        "total_error_events": int(df_sorted["error_events"].fillna(0).sum()),
        "top_session_ids": top_session_ids,
    }
    return payload


def _print_apache_report(payload: dict) -> None:
    print("Apache anomaly report:\n")
    print(f"  total_sessions_considered={payload['total_sessions_considered']}")
    print(f"  rare_hour_sessions={payload['rare_hour_sessions']}")
    print(f"  sessions_with_5xx_burst={payload['sessions_with_5xx_burst']}")
    print(f"  sessions_with_error_burst={payload['sessions_with_error_burst']}")
    print(f"  sessions_with_rare_templates={payload['sessions_with_rare_templates']}")
    print(f"  sessions_with_high_severity_ratio={payload['sessions_with_high_severity_ratio']}")
    print(f"  sessions_with_error_dominance={payload['sessions_with_error_dominance']}")
    print(f"  total_error_events={payload['total_error_events']}")
    print("  top_session_ids:")
    for session_id in payload["top_session_ids"]:
        print(f"    - {session_id}")


def _build_apache_ai_prompt(evidence) -> dict:
    extra = evidence.extra or {}

    incident = {
        "incident_id": evidence.incident_id,
        "ip": evidence.ip,
        "severity": evidence.severity,
        "attack_pattern": evidence.attack_pattern,
        "primary_user": evidence.user,
        "total_events": extra.get("error_events", 0),
        "avg_anomaly_score": extra.get("avg_anomaly_score", 0.0),
        "status_5xx": extra.get("status_5xx", 0),
        "apache_5xx_burst_max_per_minute": extra.get("apache_5xx_burst_max_per_minute", 0),
        "apache_error_burst_max_per_minute": extra.get("apache_error_burst_max_per_minute", 0),
        "apache_rare_error_message_ratio": extra.get("apache_rare_error_message_ratio", 0.0),
        "apache_rare_path_ratio": extra.get("apache_rare_path_ratio", 0.0),
        "apache_high_severity_ratio": extra.get("apache_high_severity_ratio", 0.0),
    }

    evidence_block = {
        "highlights": list(evidence.highlights),
    }

    timeline_summary = (
        f"Apache error session {evidence.incident_id} with attack pattern "
        f"'{evidence.attack_pattern}' and severity {evidence.severity}."
    )

    aggregates = {
        "total_incidents": 1,
    }

    return {
        "incident": incident,
        "evidence": evidence_block,
        "timeline_summary": timeline_summary,
        "aggregates": aggregates,
    }


def _explain_apache_session(args: argparse.Namespace, sessions, df) -> int:
    if df.empty:
        print("No sessions found.")
        return 0

    missing = _ensure_required_columns(df)
    if missing:
        print(f"scored data missing required columns: {', '.join(missing)}")
        return 1

    filtered = _apply_apache_filters(df, args)
    df_sorted = _sorted_apache_df(filtered, top=max(args.top, 1))

    if df_sorted.empty:
        print("No sessions found after filtering.")
        return 0

    if getattr(args, "first", False):
        index = 0
    else:
        index = getattr(args, "index", 0)
        if index < 0 or index >= len(df_sorted):
            print(f"Invalid index {index}. There are {len(df_sorted)} session(s) after filtering.")
            return 1

    row = df_sorted.iloc[index]
    session_id = row["session_id"]
    session = _find_session_by_id(sessions, session_id)
    if session is None:
        print(f"Session {session_id} not found in built sessions.")
        return 1

    print(f"Explaining Apache session at index {index}: session_id={session_id}")

    summary = summarize_apache_row(row)
    print(
        f"  score={summary.score:.3f} "
        f"errors={summary.error_ratio:.2f} "
        f"5xx_burst={summary.apache_5xx_burst_max_per_minute} "
        f"notes={summary.apache_notes}"
    )

    evidence = build_apache_incident_evidence(
        session,
        row,
        model_type=args.model_type,
        threshold_percentile=getattr(args, "threshold_percentile", 99.0),
    )

    if getattr(args, "format", "text") == "json":
        payload = evidence.to_dict()
        data = json.dumps(payload, indent=2)
        write_output(data, getattr(args, "output", None))
        return 0

    print("  highlights:")
    for h in evidence.highlights:
        print(f"    - {h}")

    extra = evidence.extra
    print(
        "  metrics: "
        f"status_5xx={extra.get('status_5xx', 0)} "
        f"error_events={extra.get('error_events', 0)} "
        f"rare_error_templates={extra.get('apache_rare_error_message_count', 0)} "
        f"rare_error_ratio={extra.get('apache_rare_error_message_ratio', 0.0):.2f} "
        f"rare_path_ratio={extra.get('apache_rare_path_ratio', 0.0):.2f}"
    )

    return 0


def _ai_explain_apache_session(args: argparse.Namespace, sessions, df) -> int:
    if df.empty:
        print("No sessions found.")
        return 0

    missing = _ensure_required_columns(df)
    if missing:
        print(f"scored data missing required columns: {', '.join(missing)}")
        return 1

    filtered = _apply_apache_filters(df, args)
    df_sorted = _sorted_apache_df(filtered, top=max(args.top, 1))

    if df_sorted.empty:
        print("No sessions found after filtering.")
        return 0

    if getattr(args, "first", False):
        index = 0
    else:
        index = getattr(args, "index", 0)
        if index < 0 or index >= len(df_sorted):
            print(f"Invalid index {index}. There are {len(df_sorted)} session(s) after filtering.")
            return 1

    row = df_sorted.iloc[index]
    session_id = row["session_id"]
    session = _find_session_by_id(sessions, session_id)
    if session is None:
        print(f"Session {session_id} not found in built sessions.")
        return 1

    print(f"AI-explaining Apache session at index {index}: session_id={session_id}")

    evidence = build_apache_incident_evidence(
        session,
        row,
        model_type=args.model_type,
        threshold_percentile=getattr(args, "threshold_percentile", 99.0),
    )

    prompt = _build_apache_ai_prompt(evidence)
    analysis = generate_incident_analysis(prompt)

    payload = {
        "incident_id": evidence.incident_id,
        "log_type": evidence.log_type,
        "ip": evidence.ip,
        "severity": evidence.severity,
        "attack_pattern": evidence.attack_pattern,
        "ai_analysis": analysis,
    }

    data = json.dumps(payload, indent=2)
    write_output(data, getattr(args, "output", None))
    return 0


def _report_apache_sessions(args: argparse.Namespace, df) -> int:
    if df.empty:
        print("No sessions found.")
        return 0

    missing = _ensure_required_columns(df)
    if missing:
        print(f"scored data missing required columns: {', '.join(missing)}")
        return 1

    filtered = _apply_apache_filters(df, args)
    df_sorted = _sorted_apache_df(filtered, top=args.top)

    if df_sorted.empty:
        print("No sessions found after filtering.")
        return 0

    payload = _build_apache_report_payload(df_sorted)

    if getattr(args, "format", "text") == "json":
        data = json.dumps(payload, indent=2)
        write_output(data, getattr(args, "output", None))
        return 0

    _print_apache_report(payload)
    return 0


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
        help="Number of top suspicious sessions to show or consider (default: 20).",
    )
    parser.add_argument(
        "--threshold-percentile",
        type=float,
        default=99.0,
        help="Percentile threshold used when building Apache evidence (default: 99.0).",
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Explain a single suspicious Apache session with evidence-style output.",
    )
    parser.add_argument(
        "--ai-explain",
        action="store_true",
        help="Generate AI-assisted structured analysis for a single suspicious Apache session.",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Show an aggregate report over the top suspicious Apache sessions.",
    )
    parser.add_argument(
        "--index",
        type=int,
        default=0,
        help="Zero-based index into the sorted list of sessions to explain (used with --explain/--ai-explain).",
    )
    parser.add_argument(
        "--first",
        action="store_true",
        help="Explain the first session after sorting (used with --explain/--ai-explain).",
    )
    parser.add_argument(
        "--min-score",
        type=float,
        default=None,
        help="Only include sessions at or above this anomaly/ensemble score.",
    )
    parser.add_argument(
        "--rare-hour-only",
        action="store_true",
        help="Only include sessions that occurred during unusual hours.",
    )
    parser.add_argument(
        "--min-5xx-burst",
        type=int,
        default=None,
        help="Only include sessions with at least this many 5xx events in a one-minute burst.",
    )
    parser.add_argument(
        "--min-error-events",
        type=int,
        default=None,
        help="Only include sessions with at least this many Apache error events.",
    )
    add_json_output_args(parser, "Apache sessions, explanation, AI analysis, or report")
    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    sessions, df = load_apache_sessions_for_cli(args)

    mode_count = sum(bool(x) for x in [args.explain, args.ai_explain, args.report])
    if mode_count > 1:
        print("Choose only one of --explain, --ai-explain, or --report.")
        return 1

    if args.explain:
        return _explain_apache_session(args, sessions, df)

    if args.ai_explain:
        return _ai_explain_apache_session(args, sessions, df)

    if args.report:
        return _report_apache_sessions(args, df)

    if df.empty:
        print("No sessions found.")
        return 0

    missing = _ensure_required_columns(df)
    if missing:
        print(f"scored data missing required columns: {', '.join(missing)}")
        return 1

    filtered = _apply_apache_filters(df, args)
    df_sorted = _sorted_apache_df(filtered, top=args.top)

    if df_sorted.empty:
        print("No sessions found after filtering.")
        return 0

    if getattr(args, "format", "text") == "json":
        payload = []
        for _, row in df_sorted.iterrows():
            summary = summarize_apache_row(row)
            payload.append(asdict(summary))

        data = json.dumps(payload, indent=2)
        write_output(data, getattr(args, "output", None))
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