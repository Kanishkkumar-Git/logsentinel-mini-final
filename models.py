"""
Declarative schemas for LLM-based log extraction.

The core idea: we don't write regex parsers per log format.
We declare the STRUCTURE we want, and the LLM fills it in.
"""

from typing import Literal, Optional
from pydantic import BaseModel, Field


class SecurityEvent(BaseModel):
    """A single structured security finding extracted from a chunk of raw logs."""

    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = Field(
        description="Severity of the finding"
    )
    event_type: Literal[
        "AUTH_FAILURE",
        "BRUTE_FORCE",
        "SQL_INJECTION",
        "XSS_ATTEMPT",
        "PORT_SCAN",
        "PRIVILEGE_ESCALATION",
        "SUSPICIOUS_USER_AGENT",
        "ANOMALY",
        "BENIGN",
    ] = Field(description="Category of the security event")
    source_ip: Optional[str] = Field(default=None, description="Source IP if present in logs")
    target_user: Optional[str] = Field(default=None, description="Targeted username if present")
    is_attack: bool = Field(description="Whether this represents an actual attack/malicious activity")
    confidence: float = Field(ge=0.0, le=1.0, description="Model's confidence in this classification")
    summary: str = Field(description="One or two sentence human-readable summary")
    recommended_action: str = Field(description="Short recommended remediation or next step")


class ChunkAnalysisResult(BaseModel):
    """Result of analyzing one chunk (batch) of log lines."""

    events: list[SecurityEvent]
    total_lines_analyzed: int
    highest_severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "NONE"]
