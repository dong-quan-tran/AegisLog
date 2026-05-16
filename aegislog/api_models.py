from __future__ import annotations

from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, Field


class LogRequest(BaseModel):
    content: str = Field(..., description="Raw log content as text.")
    source_type: Literal["generic", "ssh", "apache"] = Field(
        default="generic",
        description="Logical source type for the log input.",
    )
    input_format: Literal["jsonl", "syslog"] = Field(
        default="jsonl",
        description="Input format for generic logs. Ignored for ssh/apache where applicable.",
    )
    mapping: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional inline mapping config for generic logs.",
    )
    window_minutes: int = Field(
        default=15,
        ge=1,
        le=1440,
        description="Grouping window size in minutes.",
    )
    top: int = Field(
        default=5,
        ge=1,
        le=100,
        description="Maximum number of records or incidents to return.",
    )


class ExplainRequest(LogRequest):
    index: int = Field(
        default=0,
        ge=0,
        description="Zero-based incident index to explain.",
    )
    first: bool = Field(
        default=False,
        description="If true, explain the first incident and ignore index.",
    )
    use_ai: bool = Field(
        default=False,
        description="Whether to call the configured AI backend.",
    )