from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db import get_db
from app.models import Scan, Finding, ArchitectureMetric, HealthScore, AiReport, PatchProposal
from app.schemas import (
    AiDiagnoseRequest,
    AiFixesRequest,
    AiReportResponse,
    PatchProposalResponse,
    AiDataResponse,
)
from app.ai.evidence_pack import build_evidence_pack
from app.ai.client import AiClient, AiNotConfiguredError, AiValidationError

router = APIRouter(prefix="/api/scans", tags=["ai"])
ai_client = AiClient()


@router.post("/{scan_id}/ai/diagnose", response_model=AiReportResponse)
async def trigger_diagnosis(
    scan_id: str,
    payload: AiDiagnoseRequest | None = None,
    db: Session = Depends(get_db),
):
    """Generate structured AI diagnosis from repository evidence pack."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    if scan.status != "succeeded":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan is currently '{scan.status}'. Diagnosis requires a succeeded scan."
        )

    if not ai_client.is_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AI diagnosis is unavailable. Configure LLM_BASE_URL, LLM_API_KEY and LLM_MODEL in .env"
        )

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    architecture = db.query(ArchitectureMetric).filter(ArchitectureMetric.scan_id == scan_id).all()
    score = db.query(HealthScore).filter(HealthScore.scan_id == scan_id).first()

    evidence_pack = build_evidence_pack(scan, findings, architecture, score)

    try:
        validated_result, raw_model = await ai_client.generate_diagnosis(evidence_pack)
    except AiValidationError as e:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"LLM request failed: {e}")

    report = AiReport(
        scan_id=scan_id,
        kind="diagnosis",
        raw_model=raw_model,
        validated_json=validated_result.model_dump(),
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    return AiReportResponse.model_validate(report)


@router.post("/{scan_id}/ai/fixes", response_model=list[PatchProposalResponse])
async def trigger_fixes(
    scan_id: str,
    payload: AiFixesRequest,
    db: Session = Depends(get_db),
):
    """Generate safe patch proposals for specific or top findings."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    if scan.status != "succeeded":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan is currently '{scan.status}'. Patch proposals require a succeeded scan."
        )

    if not ai_client.is_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AI patch generation is unavailable. Configure LLM_BASE_URL, LLM_API_KEY and LLM_MODEL in .env"
        )

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    architecture = db.query(ArchitectureMetric).filter(ArchitectureMetric.scan_id == scan_id).all()
    score = db.query(HealthScore).filter(HealthScore.scan_id == scan_id).first()

    evidence_pack = build_evidence_pack(
        scan, findings, architecture, score, specific_finding_ids=payload.finding_ids
    )

    try:
        validated_result, raw_model = await ai_client.generate_patches(evidence_pack)
    except AiValidationError as e:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"LLM request failed: {e}")

    # Save report history
    report = AiReport(
        scan_id=scan_id,
        kind="patch",
        raw_model=raw_model,
        validated_json=validated_result.model_dump(),
    )
    db.add(report)

    created_patches = []
    for p in validated_result.patches:
        target_file = p.files_affected[0] if p.files_affected else "unknown.py"
        patch = PatchProposal(
            scan_id=scan_id,
            file_path=target_file,
            original=p.original_code,
            proposed=p.proposed_code,
            unified_diff=p.unified_diff,
            explanation=p.explanation,
            confidence=p.confidence,
            risk=p.risk,
            status="proposed",
        )
        db.add(patch)
        created_patches.append(patch)

    db.commit()
    for p in created_patches:
        db.refresh(p)

    return [PatchProposalResponse.model_validate(p) for p in created_patches]


@router.get("/{scan_id}/ai", response_model=AiDataResponse)
def get_ai_data(scan_id: str, db: Session = Depends(get_db)):
    """Retrieve saved AI reports and patch proposals."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")

    reports = db.query(AiReport).filter(AiReport.scan_id == scan_id).order_by(AiReport.created_at.desc()).all()
    patches = db.query(PatchProposal).filter(PatchProposal.scan_id == scan_id).all()

    return AiDataResponse(
        reports=[AiReportResponse.model_validate(r) for r in reports],
        patches=[PatchProposalResponse.model_validate(p) for p in patches],
    )
