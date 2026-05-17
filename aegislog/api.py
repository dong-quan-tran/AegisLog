from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from aegislog.api_models import ExplainRequest, LogRequest
from aegislog.normalized_loader import NormalizedLoadError
from aegislog.services_api import (
    generic_explain,
    generic_incidents,
    normalize_logs,
    normalized_explain,
    normalized_incidents,
)

app = FastAPI(
    title="AegisLog API",
    version="0.1.0",
    description="HTTP API for log normalization, incident grouping, and structured explain flows.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/normalize")
def post_normalize(request: LogRequest) -> dict:
    try:
        return normalize_logs(
            content=request.content,
            source_type=request.source_type,
            input_format=request.input_format,
            mapping=request.mapping,
            top=request.top,
        )
    except (NormalizedLoadError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Normalization failed: {exc}") from exc


@app.post("/generic-incidents")
def post_generic_incidents(request: LogRequest) -> dict:
    try:
        return generic_incidents(
            content=request.content,
            input_format=request.input_format,
            mapping=request.mapping,
            window_minutes=request.window_minutes,
            top=request.top,
        )
    except (NormalizedLoadError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Incident grouping failed: {exc}") from exc


@app.post("/normalized-incidents")
def post_normalized_incidents(request: LogRequest) -> dict:
    try:
        return normalized_incidents(
            content=request.content,
            source_type=request.source_type,
            input_format=request.input_format,
            mapping=request.mapping,
            window_minutes=request.window_minutes,
            top=request.top,
        )
    except (NormalizedLoadError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Normalized incident grouping failed: {exc}") from exc


@app.post("/generic-explain")
def post_generic_explain(request: ExplainRequest) -> dict:
    try:
        return generic_explain(
            content=request.content,
            input_format=request.input_format,
            mapping=request.mapping,
            window_minutes=request.window_minutes,
            index=request.index,
            first=request.first,
            use_ai=request.use_ai,
        )
    except (NormalizedLoadError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Generic explain failed: {exc}") from exc


@app.post("/normalized-explain")
def post_normalized_explain(request: ExplainRequest) -> dict:
    try:
        return normalized_explain(
            content=request.content,
            source_type=request.source_type,
            input_format=request.input_format,
            mapping=request.mapping,
            window_minutes=request.window_minutes,
            index=request.index,
            first=request.first,
            use_ai=request.use_ai,
        )
    except (NormalizedLoadError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Normalized explain failed: {exc}") from exc