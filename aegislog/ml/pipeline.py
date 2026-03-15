from sklearn.ensemble import IsolationForest
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

NUMERIC_FEATURES = [
    "event_count",
    "duration_seconds",
    "status_4xx",
    "status_5xx",
    "error_ratio",
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
