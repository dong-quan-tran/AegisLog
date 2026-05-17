from __future__ import annotations

from typing import Any, Dict, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class LogRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str = Field(
        ...,
        min_length=1,
        description="Raw log content as text.",
    )
    source_type: Literal["generic", "ssh", "apache"] = Field(
        default="generic",
        description="Logical source type for the log input.",
    )
    input_format: Literal["jsonl", "syslog"] = Field(
        default="jsonl",
        description="Input format for generic logs. Ignored for ssh/apache where applicable.",
    )
    mapping: Dict[str, Any] | None = Field(
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

    @model_validator(mode="after")
    def validate_request_rules(self) -> "LogRequest":
        if not self.content.strip():
            raise ValueError("content must not be empty or whitespace only")

        if self.source_type != "generic" and self.mapping is not None:
            raise ValueError("mapping is only supported when source_type='generic'")

        return self


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