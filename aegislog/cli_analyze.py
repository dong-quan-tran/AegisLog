from aegislog.cli_common import add_json_output_args


def register_analyze_parser(subparsers) -> None:
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
    add_json_output_args(p_analyze, "analysis results")
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