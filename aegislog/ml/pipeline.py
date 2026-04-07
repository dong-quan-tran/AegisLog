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