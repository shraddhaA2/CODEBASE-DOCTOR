from typing import Literal
from pydantic import BaseModel, Field


class DiagnosisItem(BaseModel):
    diagnosis: str = Field(..., description="Clear diagnostic summary of the issue")
    why_it_matters: str = Field(..., description="Engineering explanation of why this issue matters")
    impact: str = Field(..., description="Impact on security, maintainability, or reliability")
    recommended_action: str = Field(..., description="Specific recommended remediation steps")
    priority: Literal["critical", "high", "medium", "low"] = Field(..., description="Priority level")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score from 0.0 to 1.0")
    evidence_sufficient: bool = Field(..., description="Whether provided evidence was sufficient without speculation")
    related_finding_ids: list[str] = Field(default_factory=list, description="IDs of related findings from evidence")


class DiagnosisResult(BaseModel):
    summary: str = Field(..., description="Executive summary of repository health")
    diagnoses: list[DiagnosisItem] = Field(..., description="List of structured diagnosis items")


class PatchItem(BaseModel):
    files_affected: list[str] = Field(..., description="File paths affected by this patch")
    original_code: str = Field(..., description="Original snippet before proposed fix")
    proposed_code: str = Field(..., description="Proposed replacement snippet")
    unified_diff: str = Field(..., description="Standard unified diff representation")
    explanation: str = Field(..., description="Detailed explanation of the changes made")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score from 0.0 to 1.0")
    risk: Literal["low", "medium", "high"] = Field(..., description="Assessment of regression risk")


class PatchResult(BaseModel):
    patches: list[PatchItem] = Field(..., description="List of proposed patch items")
