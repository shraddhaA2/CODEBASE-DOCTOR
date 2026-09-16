import asyncio
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.db import get_db
from app.models import Scan, Finding, ArchitectureMetric, HealthScore
from app.schemas import (
    ScanCreateRequest,
    ScanCreateResponse,
    ScanResponse,
    FindingResponse,
    ArchitectureSummaryResponse,
    ArchitectureMetricResponse,
    HealthScoreResponse,
)
from app.security.github_url import validate_and_normalize_github_url, InvalidGitHubURLError
from app.pipeline.orchestrator import enqueue_scan

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post("", response_model=ScanCreateResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(payload: ScanCreateRequest, db: Session = Depends(get_db)):
    """Validate GitHub URL, create queued scan, and trigger background analysis."""
    try:
        normalized_url = validate_and_normalize_github_url(payload.github_url)
    except InvalidGitHubURLError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    scan = Scan(
        github_url=normalized_url,
        status="queued",
        limits=payload.limits,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Launch background worker
    asyncio.create_task(enqueue_scan(scan.id))

    return ScanCreateResponse(scan_id=scan.id)


@router.get("", response_model=list[ScanResponse])
def list_scans(limit: int = 20, db: Session = Depends(get_db)):
    """Retrieve recent scans."""
    scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(limit).all()
    return scans


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    """Retrieve scan status and metadata."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    return scan


@router.get("/{scan_id}/findings", response_model=list[FindingResponse])
def get_findings(
    scan_id: str,
    category: str | None = Query(None, description="Filter by category"),
    severity: str | None = Query(None, description="Filter by severity"),
    analyzer: str | None = Query(None, description="Filter by analyzer"),
    scope: str | None = Query(None, description="Filter by scope: source, test, generated, vendor, docs"),
    include_duplicates: bool = Query(True, description="Whether to include duplicate findings from secondary analyzers"),
    db: Session = Depends(get_db),
):
    """Retrieve findings for a scan with optional filters."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    query = db.query(Finding).filter(Finding.scan_id == scan_id)
    if category:
        query = query.filter(Finding.category == category)
    if severity:
        query = query.filter(Finding.severity == severity)
    if analyzer:
        query = query.filter(Finding.analyzer == analyzer)
    if scope:
        query = query.filter(Finding.scope == scope)
    if not include_duplicates:
        query = query.filter(Finding.is_duplicate.is_(False))

    findings = query.all()
    return findings


@router.get("/{scan_id}/architecture", response_model=ArchitectureSummaryResponse)
def get_architecture(scan_id: str, db: Session = Depends(get_db)):
    """Retrieve architecture metrics and graph summary."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    metrics = db.query(ArchitectureMetric).filter(ArchitectureMetric.scan_id == scan_id).all()

    total_modules = len(metrics)
    total_dependencies = sum(m.fan_out for m in metrics)
    circular_components = {m.circular_component_id for m in metrics if m.circular_component_id is not None}

    # Identify hubs
    sorted_hubs = sorted(metrics, key=lambda m: (m.fan_out + m.fan_in), reverse=True)[:5]
    hubs = [
        {"module": m.module, "fan_in": m.fan_in, "fan_out": m.fan_out}
        for m in sorted_hubs
    ]

    return ArchitectureSummaryResponse(
        total_modules=total_modules,
        total_dependencies=total_dependencies,
        circular_components_count=len(circular_components),
        hubs=hubs,
        metrics=[ArchitectureMetricResponse.model_validate(m) for m in metrics],
    )


@router.get("/{scan_id}/score", response_model=HealthScoreResponse)
def get_score(scan_id: str, db: Session = Depends(get_db)):
    """Retrieve health scores and complete auditable breakdown."""
    score = db.query(HealthScore).filter(HealthScore.scan_id == scan_id).first()
    if not score:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
        if scan.status in {"queued", "running"}:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Scan is still in progress.")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Health score not available.")

    return HealthScoreResponse.model_validate(score)
