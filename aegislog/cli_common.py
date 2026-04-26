import argparse


SEVERITY_CHOICES = ["low", "medium", "high"]
CONFIDENCE_CHOICES = ["low", "medium", "high"]

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}
CONFIDENCE_ORDER = {"low": 1, "medium": 2, "high": 3}


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

    if args.model_type == "iforest":
        if args.log_type == "ssh_auth":
            return "models/log_anomaly_iforest_ssh.joblib"
        return "models/log_anomaly_iforest_apache.joblib"

    if args.model_type == "ocsvm":
        if args.log_type == "ssh_auth":
            return "models/log_anomaly_ocsvm_ssh.joblib"
        return "models/log_anomaly_ocsvm_apache.joblib"

    if args.log_type == "ssh_auth":
        return "models/log_anomaly_lof_ssh.joblib"
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