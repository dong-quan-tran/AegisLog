from sklearn.ensemble import IsolationForest
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

from typing import List, Tuple
import pandas as pd
import joblib
from pathlib import Path

from aegislog.features.sessions import Session
from aegislog.features.behavioral import sessions_to_features

NUMERIC_FEATURES = [
    "event_count",
    "duration_seconds",
    "status_4xx",
    "status_5xx",
    "error_ratio",
    "error_events",
    "notice_events",
    "error_event_ratio",
]


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


def load_model(model_path: str = "models/log_anomaly_iforest.joblib"):
    return joblib.load(model_path)


def score_sessions(
    sessions: List[Session],
    model_path: str = "models/log_anomaly_iforest.joblib",
) -> pd.DataFrame:
    model = load_model(model_path)
    df = sessions_to_features(sessions)
    if df.empty:
        return df

    # IsolationForest.decision_function: higher = more normal
    scores = model.decision_function(df)
    df["anomaly_score"] = -scores  # invert so higher = more anomalous
    return df