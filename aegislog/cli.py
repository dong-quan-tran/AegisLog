import argparse

from aegislog.parsing.apache_error import parse_error_file
from aegislog.parsing.auth_ssh import parse_ssh_file
from aegislog.features.sessions import build_sessions
from aegislog.ml.pipeline import score_sessions
from aegislog.incidents import group_sessions_by_ip, summarize_incident
from aegislog.ai import build_incident_llm_prompt, explain_incident_with_llm, local_incident_explanation

def cmd_explain(args: argparse.Namespace) -> None:
    if args.log_type != "ssh_auth":
        print("Currently, explain is only implemented for ssh_auth logs.")
        return

    events = parse_ssh_file(args.log_path)
    sessions = build_sessions(events)
    df = score_sessions(sessions, model_path=args.model_path)

    if df.empty:
        print("No sessions found.")
        return

    incidents = group_sessions_by_ip(sessions, df)
    if not incidents:
        print("No incidents found.")
        return

    if args.index < 0 or args.index >= len(incidents):
        print(f"Invalid index {args.index}. There are {len(incidents)} incident(s).")
        return

    inc = incidents[args.index]

    print(f"Explaining incident at index {args.index}: {inc.incident_id}")
    print(
        f"  ip={inc.ip} severity={inc.severity} "
        f"sessions={len(inc.session_ids)} total_events={inc.total_events} "
        f"auth_failed={inc.auth_failed} auth_success={inc.auth_success} "
        f"auth_fail_ratio={inc.auth_fail_ratio:.2f} "
        f"avg_anomaly_score={inc.avg_anomaly_score:.3f}"
    )

    summary = summarize_incident(inc)
    print(f"  summary_title={summary.title}")
    print(f"  summary_description={summary.description}")

    explanation = local_incident_explanation(inc, summary)
    print("  local_explanation_begin")
    print(f"    {explanation}")
    print("  local_explanation_end")

    llm_prompt = build_incident_llm_prompt(inc, summary)
    prompt_text = explain_incident_with_llm(llm_prompt)
    print("  llm_prompt_begin")
    for line in prompt_text.splitlines():
        print(f"    {line}")
    print("  llm_prompt_end")

def cmd_incidents(args: argparse.Namespace) -> None:
    if args.log_type != "ssh_auth":
        print("Currently, incidents are only implemented for ssh_auth logs.")
        return

    events = parse_ssh_file(args.log_path)
    sessions = build_sessions(events)
    df = score_sessions(sessions, model_path=args.model_path)

    if df.empty:
        print("No sessions found.")
        return

    incidents = group_sessions_by_ip(sessions, df)
    top = incidents[: args.top]

    print(f"Top {len(top)} IP-based incidents:")
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
            f"sessions={len(inc.session_ids)} "
            f"total_events={inc.total_events} "
            f"auth_failed={inc.auth_failed} auth_success={inc.auth_success} "
            f"auth_fail_ratio={inc.auth_fail_ratio:.2f} "
            f"avg_anomaly_score={inc.avg_anomaly_score:.3f}"
        )

        summary = summarize_incident(inc)
        print(f"  summary_title={summary.title}")
        print(f"  summary_description={summary.description}")

        if args.show_local_explanation:
            explanation = local_incident_explanation(inc, summary)
            print("  local_explanation_begin")
            print(f"    {explanation}")
            print("  local_explanation_end")

        if args.print_llm_prompt:
            llm_prompt = build_incident_llm_prompt(inc, summary)
            prompt_text = explain_incident_with_llm(llm_prompt)
            print("  llm_prompt_begin")
            for line in prompt_text.splitlines():
                print(f"    {line}")
            print("  llm_prompt_end")

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

    sessions = build_sessions(events)
    df = score_sessions(sessions, model_path=args.model_path)

    if df.empty:
        print("No sessions found.")
        return

    df_sorted = df.sort_values("anomaly_score", ascending=False)
    top = df_sorted.head(args.top)

    print(f"Top {len(top)} anomalous sessions:")
    for _, row in top.iterrows():
        print(
            f"- session_id={row['session_id']} "
            f"ip={row['ip']} user={row['user']} "
            f"events={row['event_count']} "
            f"error_ratio={row['error_ratio']:.2f} "
            f"anomaly_score={row['anomaly_score']:.3f}"
        )

def main() -> None:
    parser = argparse.ArgumentParser(prog="aegislog")
    subparsers = parser.add_subparsers(dest="command", required=True)

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

    p_analyze = subparsers.add_parser("analyze", help="Analyze logs and detect incidents.")
    p_analyze.add_argument("log_path", help="Path to log file.")
    p_analyze.add_argument(
        "--model-path",
        default="models/log_anomaly_iforest.joblib",
        help="Path to trained model.",
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
    p_analyze.set_defaults(func=cmd_analyze)

    p_incidents = subparsers.add_parser(
        "incidents", help="Group anomalous sessions into simple IP-based incidents."
    )
    p_incidents.add_argument("log_path", help="Path to log file.")
    p_incidents.add_argument(
        "--model-path",
        default="models/log_anomaly_iforest_ssh.joblib",
        help="Path to trained model.",
    )
    p_incidents.add_argument(
        "--show-local-explanation",
        action="store_true",
        help="Show a simple, built-in AI-style explanation for each incident.",
    )
    p_incidents.add_argument(
        "--log-type",
        choices=["ssh_auth"],
        default="ssh_auth",
        help="Type of log file to parse (currently ssh_auth only).",
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
    p_incidents.set_defaults(func=cmd_incidents)
    p_explain = subparsers.add_parser(
        "explain", help="Explain a single SSH incident with AI-style output."
    )
    p_explain.add_argument("log_path", help="Path to log file.")
    p_explain.add_argument(
        "--model-path",
        default="models/log_anomaly_iforest_ssh.joblib",
        help="Path to trained model.",
    )
    p_explain.add_argument(
        "--log-type",
        choices=["ssh_auth"],
        default="ssh_auth",
        help="Type of log file to parse (currently ssh_auth only).",
    )
    p_explain.add_argument(
        "--index",
        type=int,
        default=0,
        help="Zero-based index into the sorted list of incidents to explain.",
    )
    p_explain.set_defaults(func=cmd_explain)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()

