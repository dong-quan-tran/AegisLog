from sklearn.ensemble import IsolationForest
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.svm import OneClassSVM 
from sklearn.neighbors import LocalOutlierFactor

from typing import List, Tuple
import pandas as pd
import joblib
from pathlib import Path

from aegislog.features.sessions import Session
from aegislog.features.behavioral import sessions_to_features

MODEL_VERSION = "iforest-v2"
MODEL_FILENAME = f"log_anomaly_{MODEL_VERSION}.joblib"
MODEL_PATH = f"models/{MODEL_FILENAME}"

NUMERIC_FEATURES = [
    "event_count",
    "duration_seconds",
    "status_4xx",
    "status_5xx",
    "error_ratio",
    "error_events",
    "notice_events",
    "error_event_ratio",
    "auth_failed",
    "auth_success",
    "auth_fail_ratio",
    "avg_events_per_second",
    "unique_paths",
    "source_count",
    "has_mixed_sources",
    "auth_failed_streak_max",
    "success_after_failure_count",
    "auth_burst_max_per_minute",
    "mean_inter_event_gap_seconds",
    "max_inter_event_gap_seconds",
    "ssh_distinct_users",
    "ssh_distinct_ips_per_user",
    "ssh_distinct_targeted_users",
    "ssh_rare_hour",
    "first_seen_ip_flag",
    "first_seen_user_flag",
    # Apache-focused features
    "apache_5xx_streak_max",
    "apache_404_burst_max_per_minute",
    "apache_5xx_burst_max_per_minute",
    "apache_distinct_paths",
    "apache_rare_path_ratio",
    "apache_rare_error_message_ratio",
    "apache_rare_hour",
]

def build_ocsvm_pipeline(
    nu: float = 0.05,
    gamma: str | float = "scale",
) -> Pipeline:
    pre = ColumnTransformer(
        [("num", StandardScaler(), NUMERIC_FEATURES)],
        remainder="drop",
    )
    model = OneClassSVM(
        kernel="rbf",
        nu=nu,
        gamma=gamma,
    )
    return Pipeline([("preprocess", pre), ("model", model)])


def _minmax_normalize(series: pd.Series) -> pd.Series:
    min_val = series.min()
    max_val = series.max()
    if pd.isna(min_val) or pd.isna(max_val) or max_val == min_val:
        return pd.Series([0.0] * len(series), index=series.index)
    return (series - min_val) / (max_val - min_val)


def add_threshold_columns(
    df: pd.DataFrame,
    score_col: str = "anomaly_score",
    threshold_percentile: float = 99.0,
) -> pd.DataFrame:
    if df.empty:
        return df

    result = df.copy()
    result["anomaly_percentile"] = result[score_col].rank(pct=True) * 100.0
    result["is_anomalous"] = result["anomaly_percentile"] >= threshold_percentile
    return result


def score_sessions_multi(
    sessions: List[Session],
    model_paths: dict[str, str],
    add_ensemble: bool = True,
) -> pd.DataFrame:
    df = sessions_to_features(sessions)
    if df.empty:
        return df

    raw_score_columns: list[str] = []
    normalized_score_columns: list[str] = []

    for model_name, model_path in model_paths.items():
        model = load_model(model_path)
        scores = model.decision_function(df)

        # Invert so higher = more anomalous, matching existing convention
        anomaly_scores = -scores

        raw_col = f"{model_name}_score"
        norm_col = f"{model_name}_score_norm"

        df[raw_col] = anomaly_scores
        df[norm_col] = _minmax_normalize(df[raw_col])

        raw_score_columns.append(raw_col)
        normalized_score_columns.append(norm_col)

    # Keep backward compatibility: if iforest exists, anomaly_score mirrors it
    if "iforest_score" in df.columns:
        df["anomaly_score"] = df["iforest_score"]
    else:
        df["anomaly_score"] = df[raw_score_columns[0]]

    if add_ensemble and normalized_score_columns:
        df["ensemble_score"] = df[normalized_score_columns].mean(axis=1)

    return df


def build_lof_pipeline(
    n_neighbors: int = 20,
    contamination: float = 0.05,
) -> Pipeline:
    pre = ColumnTransformer(
        [("num", StandardScaler(), NUMERIC_FEATURES)],
        remainder="drop",
    )
    model = LocalOutlierFactor(
        n_neighbors=n_neighbors,
        contamination=contamination,
        novelty=True,  # important for using on new data
    )
    return Pipeline([("preprocess", pre), ("model", model)])


def build_pipeline(contamination: float = 0.05) -> Pipeline:
    pre = ColumnTransformer(
        [("num", StandardScaler(), NUMERIC_FEATURES)],
        remainder="drop",
    )
    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
    )
    return Pipeline([("preprocess", pre), ("model", model)])


def load_model(model_path: str = MODEL_PATH):
    return joblib.load(model_path)


def score_sessions(
    sessions: List[Session],
    model_path: str = MODEL_PATH,
) -> pd.DataFrame:
    model = load_model(model_path)
    df = sessions_to_features(sessions)
    if df.empty:
        return df

    # IsolationForest.decision_function: higher = more normal
    scores = model.decision_function(df)
    df["anomaly_score"] = -scores  # invert so higher = more anomalous
    return df

def get_model_version() -> str:
    return MODEL_VERSION