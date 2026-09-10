from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field


class ScanCreateRequest(BaseModel):
    github_url: str = Field(..., description="HTTPS GitHub repository URL")
    limits: dict[str, Any] | None = Field(default=None, description="Optional scan limits override")


class ScanCreateResponse(BaseModel):
    scan_id: str


class ScanResponse(BaseModel):
    id: str
    github_url: str
    status: Literal["queued", "running", "succeeded", "failed"]
    error: str | None = None
    commit_sha: str | None = None
    created_at: datetime
    language_stats: dict[str, Any] | None = None

    model_config = ConfigDict(from_attributes=True)


class FindingResponse(BaseModel):
    id: str
    scan_id: str
    analyzer: str
    category: Literal["bug", "security", "dead_code", "dependency", "architecture", "quality"]
    severity: Literal["critical", "high", "medium", "low", "info"]
    rule_id: str
    file_path: str
    start_line: int | None = None
    end_line: int | None = None
    message: str
    evidence: dict[str, Any] | None = None
    redacted_snippet: str | None = None

    model_config = ConfigDict(from_attributes=True)


class ArchitectureMetricResponse(BaseModel):
    id: str
    scan_id: str
    module: str
    fan_in: int
    fan_out: int
    circular_component_id: int | None = None

    model_config = ConfigDict(from_attributes=True)


class ArchitectureSummaryResponse(BaseModel):
    total_modules: int
    total_dependencies: int
    circular_components_count: int
    hubs: list[dict[str, Any]]
    metrics: list[ArchitectureMetricResponse]


class HealthScoreResponse(BaseModel):
    scan_id: str
    security: float
    architecture: float
    maintainability: float
    performance: float
    code_quality: float
    dependencies: float
    overall: float
    breakdown: dict[str, Any]

    model_config = ConfigDict(from_attributes=True)


class AiDiagnoseRequest(BaseModel):
    pass


class AiFixesRequest(BaseModel):
    finding_ids: list[str] | None = None


class PatchProposalResponse(BaseModel):
    id: str
    scan_id: str
    file_path: str
    original: str
    proposed: str
    unified_diff: str
    explanation: str
    confidence: float
    risk: Literal["low", "medium", "high"]
    status: str

    model_config = ConfigDict(from_attributes=True)


class AiReportResponse(BaseModel):
    id: str
    scan_id: str
    kind: str
    validated_json: dict[str, Any] | list[Any]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AiDataResponse(BaseModel):
    reports: list[AiReportResponse]
    patches: list[PatchProposalResponse]
