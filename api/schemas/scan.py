from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


class FusionMetadataSchema(BaseModel):
    fusion_method: str = Field(..., description="Fusion method applied")
    payload_type: str = Field(..., description="Classified payload category")
    ml_weight: float = Field(..., description="Weight assigned to ML probability")
    heuristic_weight: float = Field(..., description="Weight assigned to Heuristic score")
    linear_score: float = Field(..., description="Linear score before floor overrides")
    floor_applied: bool = Field(..., description="True if critical floor override was triggered")
    ml_probability: Optional[float] = Field(None, description="Raw ML model prediction probability")
    heuristic_score: int = Field(..., description="Raw heuristic risk score")


class RiskIndicatorSchema(BaseModel):
    rule_id: str = Field(..., description="Unique rule identifier")
    category: str = Field(..., description="Rule category")
    severity: str = Field(..., description="Severity level (LOW, MEDIUM, HIGH, CRITICAL)")
    weight: int = Field(..., description="Assigned rule weight points")
    detected: bool = Field(True, description="True if indicator was detected")
    reason: str = Field(..., description="Security explanation")
    evidence: str = Field("", description="Extracted payload evidence")


class ExplanationSchema(BaseModel):
    summary: str = Field(..., description="Human-readable executive summary")
    why_dangerous: List[str] = Field(default_factory=list, description="List of detected threat explanations")
    recommended_action: str = Field(..., description="Recommended user security action")


class ScanResponseSchema(BaseModel):
    success: bool = Field(True, description="Scanning status")
    scan_id: str = Field(..., description="Unique analysis transaction ID")
    timestamp: str = Field(..., description="ISO 8601 analysis timestamp")
    payload: str = Field(..., description="Decoded QR text payload")
    payload_type: str = Field(..., description="Payload type (URL, UPI_PAYMENT, TEXT, etc.)")
    ml_probability: Optional[float] = Field(None, description="Statistical ML risk probability (0.0 to 1.0)")
    heuristic_score: int = Field(..., description="Normalized heuristic risk score (0 to 100)")
    final_risk_score: int = Field(..., description="Fused composite risk score (0 to 100)")
    risk_level: str = Field(..., description="Final risk level (LOW, MEDIUM, HIGH, CRITICAL)")
    decision: str = Field(..., description="Security decision (ALLOW, WARN, BLOCK)")
    fusion_metadata: FusionMetadataSchema = Field(..., description="Mathematical fusion metadata")
    indicators: List[RiskIndicatorSchema] = Field(default_factory=list, description="Detected security indicators")
    explanation: ExplanationSchema = Field(..., description="Explainability details")
    scam_category: Optional[str] = Field(None, description="Determined scam category")
    decision_timeline: List[Dict[str, Any]] = Field(default_factory=list, description="7-stage pipeline execution timeline")



class ErrorDetailSchema(BaseModel):
    code: str = Field(..., description="Error classification code")
    message: str = Field(..., description="Human readable error message")
    stage: Optional[str] = Field(None, description="Pipeline stage where failure occurred")


class ErrorResponseSchema(BaseModel):
    success: bool = Field(False, description="Scan status")
    error: ErrorDetailSchema = Field(..., description="Detailed error information")
