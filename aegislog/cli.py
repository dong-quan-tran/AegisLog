import argparse
import json

from aegislog.parsing.apache_error import parse_error_file
from aegislog.parsing.auth_ssh import parse_ssh_file
from aegislog.features.sessions import build_sessions

from aegislog.ml.pipeline import (
    score_sessions,
    score_sessions_multi,
    add_threshold_columns,
)

from aegislog.ai import (
    build_incident_llm_prompt,
    explain_incident_with_llm,
    local_incident_explanation,
)

from aegislog.incidents import (
    group_sessions_to_incidents,
    summarize_incident,
    build_incident_timeline,
    build_incident_report,
)

from aegislog.ai_client import call_llm_for_incident, LLMConfigError


SEVERITY_CHOICES = ["low", "medium", "high"]
CONFIDENCE_CHOICES = ["low", "medium", "high"]

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}
CONFIDENCE_ORDER = {"low": 1, "medium": 2, "high": 3}

SSH_ATTACK_PATTERN_CHOICES = [
    "brute_force",
    "password_spray",
    "possible_compromise",
    "low_signal",
    "suspicious_auth_activity",
]


def filter_incidents_by_patterns(
    incidents,
    patterns: list[str] | None = None,
):
    if not patterns:
        return incidents

    allowed = set(patterns)
    return [
        inc
        for inc in incidents
        if getattr(inc, "attack_pattern", None) in allowed
    ]


def sort_incidents(incidents, sort_by: str = "severity"):
    if sort_by == "avg_score":
        return sorted(
            incidents,
            key=lambda inc: (inc.avg_anomaly_score, inc.total_events),
            reverse=True,
        )

    if sort_by == "auth_fail_ratio":
        return sorted(
            incidents,
            key=lambda inc: (inc.auth_fail_ratio, inc.auth_failed, inc.total_events),
            reverse=True,
        )

    if sort_by == "total_events":
        return sorted(
            incidents,
            key=lambda inc: (inc.total_events, inc.auth_failed, inc.avg_anomaly_score),
            reverse=True,
        )

    # default: severity
    return sorted(
        incidents,
        key=lambda inc: (
            SEVERITY_ORDER.get(getattr(inc, "severity", "low"), 0),
            inc.avg_anomaly_score,
            inc.total_events,
        ),
        reverse=True,
    )


def filter_incidents_by_thresholds(
    incidents,
    min_severity: str | None = None,
    min_confidence: str | None = None,
):
    if not min_severity and not min_confidence:
        return incidents

    def keep(inc):
        if min_severity:
            if SEVERITY_ORDER.get(inc.severity, 0) < SEVERITY_ORDER[min_severity]:
                return False

        if min_confidence:
            conf = getattr(inc, "confidence", None)
            # Treat missing confidence as below any requested minimum.
            if conf is None:
                return False
            if CONFIDENCE_ORDER.get(conf, 0) < CONFIDENCE_ORDER[min_confidence]:
                return False

        return True

    return [inc for inc in incidents if keep(inc)]


def write_output(data: str, output_path: str | None) -> None:
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(data + "\n")
    else:
        print(data)


def session_row_to_dict(row) -> dict:
    user = row["user"]
    if user != user:
        user = None

    ip = row["ip"]
    if ip != ip:
        ip = None

    result = {
        "session_id": row["session_id"],
        "ip": ip,
        "user": user,
        "event_count": int(row["event_count"]),
        "error_ratio": float(row["error_ratio"]),
        "anomaly_score": float(row["anomaly_score"]),
    }

    optional_score_fields = [
        "iforest_score",
        "iforest_score_norm",
        "ocsvm_score",
        "ocsvm_score_norm",
        "lof_score",
        "lof_score_norm",
        "ensemble_score",
        "anomaly_percentile",
    ]

    for field in optional_score_fields:
        if field in row:
            result[field] = float(row[field])

    if "is_anomalous" in row:
        result["is_anomalous"] = bool(row["is_anomalous"])

    return result


def resolve_model_path(args) -> str:
    if args.model_path:
        return args.model_path

    # Defaults per model/log-type combo
    if args.model_type == "iforest":
        if args.log_type == "ssh_auth":
            return "models/log_anomaly_iforest_ssh.joblib"
        else:
            return "models/log_anomaly_iforest_apache.joblib"
    if args.model_type == "ocsvm":
        if args.log_type == "ssh_auth":
            return "models/log_anomaly_ocsvm_ssh.joblib"
        else:
            return "models/log_anomaly_ocsvm_apache.joblib"
    # lof
    if args.log_type == "ssh_auth":
        return "models/log_anomaly_lof_ssh.joblib"
    else:
        return "models/log_anomaly_lof_apache.joblib"


def resolve_multi_model_paths(args) -> dict[str, str]:
    paths: dict[str, str] = {}

    if args.log_type == "ssh_auth":
        paths["iforest"] = "models/log_anomaly_iforest_ssh.joblib"
        paths["ocsvm"] = "models/log_anomaly_ocsvm_ssh.joblib"
        paths["lof"] = "models/log_anomaly_lof_ssh.joblib"
    else:
        paths["iforest"] = "models/log_anomaly_iforest_apache.joblib"
        paths["ocsvm"] = "models/log_anomaly_ocsvm_apache.joblib"
        paths["lof"] = "models/log_anomaly_lof_apache.joblib"

    return paths


def incident_to_dict(inc, summary, explanation, llm_prompt) -> dict:
    return {
        "incident": {
            "incident_id": inc.incident_id,
            "ip": inc.ip,
            "severity": inc.severity,
            "severity_reason": getattr(inc, "severity_reason", None),
            "confidence": getattr(inc, "confidence", None),
            "confidence_reason": getattr(inc, "confidence_reason", None),
            "priority": getattr(inc, "priority", None),
            "priority_score": getattr(inc, "priority_score", None),
            "priority_reason": getattr(inc, "priority_reason", None),
            "attack_pattern": getattr(inc, "attack_pattern", None),
            "attack_pattern_reason": getattr(inc, "attack_pattern_reason", None),
            "session_ids": inc.session_ids,
            "total_events": inc.total_events,
            "avg_anomaly_score": inc.avg_anomaly_score,
            "auth_failed": inc.auth_failed,
            "auth_success": inc.auth_success,
            "auth_fail_ratio": inc.auth_fail_ratio,
            "first_seen": inc.first_seen.isoformat() if inc.first_seen else None,
            "last_seen": inc.last_seen.isoformat() if inc.last_seen else None,
            "primary_user": getattr(inc, "primary_user", None),
            "targeted_users": getattr(inc, "targeted_users", []),
        },
        "summary": {
            "title": summary.title,
            "description": summary.description,
        },
        "local_explanation": explanation,
        "llm_prompt": llm_prompt.prompt,
    }


def timeline_entry_to_dict(entry) -> dict:
    return {
        "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
        "session_id": entry.session_id,
        "ip": entry.ip,
        "user": entry.user,
        "auth_failed": entry.auth_failed,
        "auth_success": entry.auth_success,
        "event_count": entry.event_count,
        "anomaly_score": entry.anomaly_score,
        "event_type": entry.event_type,
    }


def load_ssh_incidents_for_cli(
    args: argparse.Namespace,
    *,
    anomalous_only: bool = False,
    restrict_sessions_to_df: bool = True,
):
    """
    Shared helper for SSH incident commands.

    Parameters
    ----------
    anomalous_only:
        If True, keep only sessions flagged as anomalous after thresholding.
    restrict_sessions_to_df:
        If True, keep only Session objects whose session_id appears in the
        post-filter DataFrame before grouping incidents.
    """
    events = parse_ssh_file(args.log_path)
    sessions = build_sessions(events)
    model_path = resolve_model_path(args)
    df = score_sessions(sessions, model_path=model_path)

    if df.empty:
        return sessions, df, []

    sort_col = "ensemble_score" if "ensemble_score" in df.columns else "anomaly_score"
    df = add_threshold_columns(
        df,
        score_col=sort_col,
        threshold_percentile=getattr(args, "threshold_percentile", 99.0),
    )

    if anomalous_only:
        df = df[df["is_anomalous"]]
        if df.empty:
            return sessions, df, []

    if restrict_sessions_to_df:
        allowed_ids = set(df["session_id"].tolist())
        sessions = [s for s in sessions if s.session_id in allowed_ids]

    incidents = group_sessions_to_incidents(sessions, df)
    return sessions, df, incidents


# ---- Parser helpers -----------------------------------------------------


def add_ssh_source_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("log_path", help="Path to log file.")
    parser.add_argument(
        "--log-type",
        choices=["ssh_auth"],
        default="ssh_auth",
        help="Type of log file to parse (currently ssh_auth only).",
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


def add_json_output_args(parser: argparse.ArgumentParser, noun: str) -> None:
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help=f"Output format for {noun} (default: text).",
    )
    parser.add_argument(
        "--output",
        help="Optional path to write JSON output instead of stdout.",
    )


def add_incident_filter_args(
    parser: argparse.ArgumentParser,
    *,
    severity_help: str = "Only include incidents at or above this severity.",
    confidence_help: str = "Only include incidents at or above this confidence level.",
    pattern_help: str = (
        "Filter incidents by attack pattern; can be specified multiple times."
    ),
    pattern_choices: list[str] | None = None,
) -> None:
    if pattern_choices is None:
        pattern_choices = SSH_ATTACK_PATTERN_CHOICES

    parser.add_argument(
        "--min-severity",
        choices=SEVERITY_CHOICES,
        help=severity_help,
    )
    parser.add_argument(
        "--min-confidence",
        choices=CONFIDENCE_CHOICES,
        help=confidence_help,
    )
    parser.add_argument(
        "--pattern",
        dest="patterns",
        choices=pattern_choices,
        action="append",
        help=pattern_help,
    )


# ---- Command implementations -------------------------------------------


def cmd_explain(args: argparse.Namespace) -> None:
    if args.log_type != "ssh_auth":
        print("Currently, explain is only implemented for ssh_auth logs.")
        return

    sessions, df, incidents = load_ssh_incidents_for_cli(
        args,
        anomalous_only=getattr(args, "alerts_only", False),
        restrict_sessions_to_df=True,
    )

    if df.empty:
        print("No sessions found.")
        return

    if not incidents:
        print("No incidents found.")
        return

    incidents = filter_incidents_by_thresholds(
        incidents,
        min_severity=getattr(args, "min_severity", None),
        min_confidence=getattr(args, "min_confidence", None),
    )

    incidents = filter_incidents_by_patterns(
        incidents,
        patterns=getattr(args, "patterns", None),
    )

    if not incidents:
        print("No incidents matched the specified severity/confidence/pattern filters.")
        return

    if getattr(args, "first", False):
        inc = incidents[0]
        index = 0
    else:
        if args.index < 0 or args.index >= len(incidents):
            print(
                f"Invalid index {args.index}. There are {len(incidents)} "
                f"incident(s) after filtering."
            )
            return
        inc = incidents[args.index]
        index = args.index

    print(f"Explaining incident at index {index}: {inc.incident_id}")
    print(
        f"  ip={inc.ip} severity={inc.severity} "
        f"confidence={getattr(inc, 'confidence', 'unknown')} "
        f"priority={getattr(inc, 'priority', 'unknown')} "
        f"pattern={getattr(inc, 'attack_pattern', 'unknown')} "
        f"priority_score={getattr(inc, 'priority_score', 'unknown')} "
        f"sessions={len(inc.session_ids)} total_events={inc.total_events} "
        f"auth_failed={inc.auth_failed} auth_success={inc.auth_success} "
        f"auth_fail_ratio={inc.auth_fail_ratio:.2f} "
        f"avg_anomaly_score={inc.avg_anomaly_score:.3f}"
    )

    if getattr(inc, "severity_reason", None):
        print(f"  severity_reason={inc.severity_reason}")

    if getattr(inc, "confidence_reason", None):
        print(f"  confidence_reason={inc.confidence_reason}")

    if getattr(inc, "priority_reason", None):
        print(f"  priority_reason={inc.priority_reason}")

    if getattr(inc, "attack_pattern_reason", None):
        print(f"  attack_pattern_reason={inc.attack_pattern_reason}")

    summary = summarize_incident(inc)
    print(f"  summary_title={summary.title}")
    print(f"  summary_description={summary.description}")

    explanation = local_incident_explanation(inc, summary)
    print("  local_explanation_begin")
    print(f"    {explanation}")
    print("  local_explanation_end")

    llm_prompt = build_incident_llm_prompt(inc, summary)

    if getattr(args, "format", "text") == "json":
        payload = incident_to_dict(inc, summary, explanation, llm_prompt)
        data = json.dumps(payload, indent=2)
        write_output(data, getattr(args, "output", None))
        return

    if getattr(args, "use_llm", False):
        try:
            llm_response = call_llm_for_incident(llm_prompt)
            print("  llm_response_begin")
            for line in llm_response.splitlines():
                print(f"    {line}")
            print("  llm_response_end")
        except LLMConfigError as e:
            print(f"  [LLM disabled] {e}")
    else:
        prompt_text = explain_incident_with_llm(llm_prompt)
        print("  llm_prompt_begin")
        for line in prompt_text.splitlines():
            print(f"    {line}")
        print("  llm_prompt_end")


def cmd_incidents(args: argparse.Namespace) -> None:
    if args.log_type != "ssh_auth":
        print("Currently, incidents are only implemented for ssh_auth logs.")
        return

    sessions, df, incidents = load_ssh_incidents_for_cli(
        args,
        anomalous_only=getattr(args, "alerts_only", False),
        restrict_sessions_to_df=True,
    )

    if df.empty:
        print("No sessions found.")
        return

    if not incidents:
        print("No incidents found.")
        return

    incidents = filter_incidents_by_thresholds(
        incidents,
        min_severity=getattr(args, "min_severity", None),
        min_confidence=getattr(args, "min_confidence", None),
    )

    incidents = filter_incidents_by_patterns(
        incidents,
        patterns=getattr(args, "patterns", None),
    )

    if not incidents:
        print("No incidents found after applying severity/confidence/pattern filters.")
        return

    incidents = sort_incidents(
        incidents,
        sort_by=getattr(args, "sort_by", "severity"),
    )

    top = incidents[: args.top]

    if getattr(args, "format", "text") == "json":
        payload = []
        for inc in top:
            summary = summarize_incident(inc)
            explanation = local_incident_explanation(inc, summary)
            llm_prompt = build_incident_llm_prompt(inc, summary)
            payload.append(incident_to_dict(inc, summary, explanation, llm_prompt))

        data = json.dumps(payload, indent=2)
        write_output(data, getattr(args, "output", None))
        return

    print(f"Top {len(top)} IP-based incidents (sorted by {args.sort_by}):")
    for inc in top:
        if inc.first_seen and inc.last_seen:
            time_window = (
                f"{inc.first_seen.isoformat()}..{inc.last_seen.isoformat()}"
            )
        else:
            time_window = "unknown"

        print(
            f"- incident_id={inc.incident_id} ip={inc.ip} "
            f"severity={inc.severity} "
            f"priority={getattr(inc, 'priority', 'unknown')} "
            f"pattern={getattr(inc, 'attack_pattern', 'unknown')} "
            f"time_window={time_window} "
            f"sessions={len(inc.session_ids)} "
            f"total_events={inc.total_events} "
            f"auth_failed={inc.auth_failed} auth_success={inc.auth_success} "
            f"auth_fail_ratio={inc.auth_fail_ratio:.2f} "
            f"avg_anomaly_score={inc.avg_anomaly_score:.3f}"
        )

        if getattr(inc, "severity_reason", None):
            print(f"  severity_reason={inc.severity_reason}")

        if getattr(inc, "confidence", None):
            print(f"  confidence={inc.confidence}")

        if getattr(inc, "confidence_reason", None):
            print(f"  confidence_reason={inc.confidence_reason}")

        if getattr(inc, "primary_user", None):
            print(f"  primary_user={inc.primary_user}")

        if getattr(inc, "targeted_users", None):
            print(f"  targeted_users={','.join(inc.targeted_users)}")

        if getattr(inc, "priority_reason", None):
            print(f"  priority_reason={inc.priority_reason}")

        if getattr(inc, "attack_pattern_reason", None):
            print(f"  attack_pattern_reason={inc.attack_pattern_reason}")

        summary = summarize_incident(inc)
        print(f"  summary_title={summary.title}")
        print(f"  summary_description={summary.description}")

        if getattr(args, "show_timeline", False):
            timeline = build_incident_timeline(inc, sessions, df)
            print("  timeline_begin")
            for entry in timeline:
                ts = entry.timestamp.isoformat() if entry.timestamp else "unknown"
                print(
                    "    "
                    f"time={ts} "
                    f"session_id={entry.session_id} "
                    f"event_type={entry.event_type} "
                    f"user={entry.user} "
                    f"auth_failed={entry.auth_failed} "
                    f"auth_success={entry.auth_success} "
                    f"events={entry.event_count} "
                    f"anomaly_score={entry.anomaly_score:.3f}"
                )
            print("  timeline_end")

        if getattr(args, "show_local_explanation", False):
            explanation = local_incident_explanation(inc, summary)
            print("  local_explanation_begin")
            print(f"    {explanation}")
            print("  local_explanation_end")

        if getattr(args, "print_llm_prompt", False):
            llm_prompt = build_incident_llm_prompt(inc, summary)
            prompt_text = explain_incident_with_llm(llm_prompt)
            print("  llm_prompt_begin")
            for line in prompt_text.splitlines():
                print(f"    {line}")
            print("  llm_prompt_end")


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


def cmd_analyze(args: argparse.Namespace) -> None:
    if args.log_type == "apache_error":
        events = parse_error_file(args.log_path)
    else:
        events = parse_ssh_file(args.log_path)

    # Apply profile shortcuts first, if any
    if getattr(args, "profile", None) == "apache":
        args.log_type = "apache_error"
        if args.model_path is None:
            args.model_path = "models/log_anomaly_iforest_apache.joblib"
    elif getattr(args, "profile", None) == "ssh":
        args.log_type = "ssh_auth"
        if args.model_path is None:
            args.model_path = "models/log_anomaly_iforest_ssh.joblib"

    sessions = build_sessions(events)

    if getattr(args, "multi_score", False):
        model_paths = resolve_multi_model_paths(args)
        df = score_sessions_multi(sessions, model_paths=model_paths, add_ensemble=True)
    else:
        model_path = resolve_model_path(args)
        df = score_sessions(sessions, model_path=model_path)

    if df.empty:
        print("No sessions found.")
        return

    sort_col = "ensemble_score" if "ensemble_score" in df.columns else "anomaly_score"
    df = add_threshold_columns(
        df,
        score_col=sort_col,
        threshold_percentile=args.threshold_percentile,
    )

    if getattr(args, "alerts_only", False):
        df = df[df["is_anomalous"]]

    df_sorted = df.sort_values(sort_col, ascending=False)
    top = df_sorted.head(args.top)

    if getattr(args, "format", "text") == "json":
        payload = [session_row_to_dict(row) for _, row in top.iterrows()]
        data = json.dumps(payload, indent=2)
        write_output(data, getattr(args, "output", None))
        return

    print(f"Top {len(top)} anomalous sessions:")
    for _, row in top.iterrows():
        parts = [
            f"session_id={row['session_id']}",
            f"ip={row['ip']}",
            f"user={row['user']}",
            f"events={row['event_count']}",
            f"error_ratio={row['error_ratio']:.2f}",
            f"anomaly_score={row['anomaly_score']:.3f}",
            f"anomaly_percentile={row['anomaly_percentile']:.1f}",
            f"is_anomalous={bool(row['is_anomalous'])}",
        ]

        if "iforest_score" in row.index:
            parts.append(f"iforest_score={row['iforest_score']:.3f}")
        if "ocsvm_score" in row.index:
            parts.append(f"ocsvm_score={row['ocsvm_score']:.3f}")
        if "lof_score" in row.index:
            parts.append(f"lof_score={row['lof_score']:.3f}")
        if "ensemble_score" in row.index:
            parts.append(f"ensemble_score={row['ensemble_score']:.3f}")

        print("- " + " ".join(parts))


def cmd_report(args: argparse.Namespace) -> None:
    if args.log_type != "ssh_auth":
        print("Currently, report is only implemented for ssh_auth logs.")
        return

    # Load and score sessions, then group into incidents using the shared helper.
    sessions, df, incidents = load_ssh_incidents_for_cli(
        args,
        anomalous_only=getattr(args, "alerts_only", False),
        restrict_sessions_to_df=True,
    )

    total_sessions = len(sessions)

    if df.empty:
        print("No sessions found.")
        return

    anomalous_df = df[df["is_anomalous"]]
    anomalous_sessions = len(anomalous_df)

    if anomalous_sessions == 0:
        print("No anomalous sessions found; no incidents to report.")
        return

    incidents = filter_incidents_by_thresholds(
        incidents,
        min_severity=getattr(args, "min_severity", None),
        min_confidence=getattr(args, "min_confidence", None),
    )

    incidents = filter_incidents_by_patterns(
        incidents,
        patterns=getattr(args, "patterns", None),
    )

    if not incidents:
        print("No incidents matched the specified severity/confidence/pattern filters.")
        return

    report = build_incident_report(
        incidents,
        total_sessions=total_sessions,
        anomalous_sessions=anomalous_sessions,
        top_n=args.top,
    )

    if getattr(args, "format", "text") == "json":
        data = json.dumps(report, indent=2)
        write_output(data, getattr(args, "output", None))
        return

    print("Incident report:")
    print(f"  total_sessions={report.get('total_sessions', 0)}")
    print(f"  anomalous_sessions={report.get('anomalous_sessions', 0)}")
    print(
        "  anomalous_session_percent="
        f"{report.get('anomalous_session_percent', 0.0):.2f}"
    )
    print(f"  total_incidents={report['total_incidents']}")
    print(f"  severity_counts={report['severity_counts']}")
    print(f"  confidence_counts={report['confidence_counts']}")

    if report["top_incident_ips"]:
        print("  top_incident_ips:")
        for item in report["top_incident_ips"]:
            print(
                f"    ip={item['ip']} incident_count={item['incident_count']}"
            )

    if report["top_targeted_users"]:
        print("  top_targeted_users:")
        for item in report["top_targeted_users"]:
            print(
                f"    user={item['user']} incident_count={item['incident_count']}"
            )


# ---- Main / parser setup ------------------------------------------------


def main(argv: list[str] | None = None) -> None:
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

    p_analyze = subparsers.add_parser(
        "analyze", help="Analyze logs and print top anomalous sessions."
    )
    p_analyze.add_argument("log_path", help="Path to log file.")
    p_analyze.add_argument(
        "--model-path",
        default=None,
        help="Path to trained model (defaults depend on log-type/profile).",
    )
    p_analyze.add_argument(
        "--log-type",
        choices=["apache_error", "ssh_auth"],
        default="apache_error",
        help="Type of log file to parse.",
    )
    p_analyze.add_argument(
        "--top",
        type=int,
        default=5,
        help="Number of most anomalous sessions to print.",
    )
    p_analyze.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format for analysis results (default: text).",
    )
    p_analyze.add_argument(
        "--output",
        help="Optional path to write JSON output instead of stdout.",
    )
    p_analyze.add_argument(
        "--profile",
        choices=["apache", "ssh"],
        help="Shortcut to set common log-type/model-path combos (apache, ssh).",
    )
    p_analyze.add_argument(
        "--model-type",
        choices=["iforest", "ocsvm", "lof"],
        default="iforest",
        help="Anomaly model to use for scoring.",
    )
    p_analyze.add_argument(
        "--multi-score",
        action="store_true",
        help="Score sessions with all available models and include normalized/ensemble scores.",
    )
    p_analyze.add_argument(
        "--threshold-percentile",
        type=float,
        default=99.0,
        help="Percentile threshold for flagging anomalous sessions (default: 99.0).",
    )
    p_analyze.add_argument(
        "--alerts-only",
        action="store_true",
        help="Show only sessions at or above the anomaly threshold.",
    )
    p_analyze.set_defaults(func=cmd_analyze)

    # incidents
    p_incidents = subparsers.add_parser(
        "incidents", help="Group anomalous sessions into simple IP-based incidents."
    )
    add_ssh_source_args(p_incidents)
    add_json_output_args(p_incidents, "incidents")
    p_incidents.add_argument(
        "--show-local-explanation",
        action="store_true",
        help="Show a simple, built-in AI-style explanation for each incident.",
    )
    p_incidents.add_argument(
        "--top",
        type=int,
        default=5,
        help="Number of top incidents to print.",
    )
    p_incidents.add_argument(
        "--print-llm-prompt",
        action="store_true",
        help="For each incident, print a ready-to-send LLM explanation prompt.",
    )
    p_incidents.add_argument(
        "--threshold-percentile",
        type=float,
        default=99.0,
        help="Percentile threshold for flagging anomalous sessions before grouping incidents (default: 99.0).",
    )
    p_incidents.add_argument(
        "--alerts-only",
        action="store_true",
        help="Group incidents from only threshold-flagged anomalous sessions.",
    )
    p_incidents.add_argument(
        "--show-timeline",
        action="store_true",
        help="Show a per-incident session timeline ordered by time.",
    )
    p_incidents.add_argument(
        "--sort-by",
        choices=["severity", "avg_score", "auth_fail_ratio", "total_events"],
        default="severity",
        help="Sort incidents before applying --top (default: severity).",
    )
    add_incident_filter_args(
        p_incidents,
        severity_help="Only include incidents at or above this severity.",
        confidence_help="Only include incidents at or above this confidence level.",
        pattern_help=(
            "Filter incidents by attack pattern; can be specified multiple "
            "times (e.g. --pattern brute_force --pattern password_spray)."
        ),
    )
    p_incidents.set_defaults(func=cmd_incidents)

    # explain
    p_explain = subparsers.add_parser(
        "explain", help="Explain a single SSH incident with AI-style output."
    )
    add_ssh_source_args(p_explain)
    add_json_output_args(p_explain, "the explanation")
    p_explain.add_argument(
        "--index",
        type=int,
        default=0,
        help="Zero-based index into the sorted list of incidents to explain.",
    )
    p_explain.add_argument(
        "--use-llm",
        action="store_true",
        help=(
            "If set, call a real LLM to generate an incident explanation "
            "(requires OPENAI_API_KEY)."
        ),
    )
    p_explain.add_argument(
        "--threshold-percentile",
        type=float,
        default=99.0,
        help=(
            "Percentile threshold for flagging anomalous sessions before "
            "grouping incidents for explanation (default: 99.0)."
        ),
    )
    p_explain.add_argument(
        "--first",
        action="store_true",
        help="Explain the first incident after applying any severity/confidence/pattern filters.",
    )
    add_incident_filter_args(
        p_explain,
        severity_help=(
            "Only consider incidents at or above this severity when "
            "selecting by index."
        ),
        confidence_help=(
            "Only consider incidents at or above this confidence when "
            "selecting by index."
        ),
        pattern_help=(
            "Only consider incidents whose attack_pattern matches one of the "
            "given values; can be specified multiple times."
        ),
    )
    p_explain.set_defaults(func=cmd_explain)

    # report
    p_report = subparsers.add_parser(
        "report",
        help="Summarize anomalous sessions and grouped incidents with aggregate metrics.",
    )
    add_ssh_source_args(p_report)
    add_json_output_args(p_report, "the report")
    p_report.add_argument(
        "--multi-score",
        action="store_true",
        help="Score sessions with all available models and include normalized/ensemble scores.",
    )
    p_report.add_argument(
        "--threshold-percentile",
        type=float,
        default=99.0,
        help="Percentile threshold for flagging anomalous sessions before reporting (default: 99.0).",
    )
    p_report.add_argument(
        "--top",
        type=int,
        default=5,
        help="Number of top IPs/users to include in the report.",
    )
    p_report.add_argument(
        "--alerts-only",
        action="store_true",
        help="Build the report from only threshold-flagged anomalous sessions.",
    )
    add_incident_filter_args(
        p_report,
        severity_help="Only include incidents at or above this severity in the report.",
        confidence_help=(
            "Only include incidents at or above this confidence level in the report."
        ),
        pattern_help=(
            "Only include incidents whose attack_pattern matches one of the "
            "given values in the report; can be specified multiple times."
        ),
    )
    p_report.set_defaults(func=cmd_report)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()