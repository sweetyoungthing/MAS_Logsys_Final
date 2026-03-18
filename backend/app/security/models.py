"""Security domain models for request/response risk analysis."""

from typing import Any, Dict, List, Literal

from pydantic import BaseModel, Field


RiskLevel = Literal["none", "low", "medium", "high", "critical"]


class SecurityFinding(BaseModel):
    """Structured evidence for a detected security risk."""

    category: str = Field(..., description="Finding category")
    severity: int = Field(..., ge=1, le=5, description="Severity level from 1 to 5")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score")
    evidence: str = Field(..., description="Human-readable evidence snippet")


class SecurityAssessment(BaseModel):
    """Risk assessment result produced by the security analyzer."""

    blocked: bool = Field(..., description="Whether the payload should be blocked")
    risk_level: RiskLevel = Field(..., description="Overall risk level")
    risk_score: int = Field(..., ge=0, le=100, description="Overall risk score")
    message: str = Field(..., description="Display message for clients")
    findings: List[SecurityFinding] = Field(default_factory=list, description="Detailed findings")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Auxiliary metadata")


class SecurityErrorResponse(BaseModel):
    """Standardized response body for security interception."""

    success: bool = Field(default=False, description="Whether the request succeeded")
    message: str = Field(..., description="Display message")
    error_code: str = Field(default="SECURITY_RISK_BLOCKED", description="Machine-readable error code")
    risk_level: RiskLevel = Field(..., description="Overall risk level")
    risk_score: int = Field(..., ge=0, le=100, description="Overall risk score")
    findings: List[SecurityFinding] = Field(default_factory=list, description="Detailed findings")
