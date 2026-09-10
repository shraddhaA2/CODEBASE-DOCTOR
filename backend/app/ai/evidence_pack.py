import json
from typing import Any
from app.config import settings
from app.models import Scan, Finding, ArchitectureMetric, HealthScore
from app.security.redact import redact_dict


SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def build_evidence_pack(
    scan: Scan,
    findings: list[Finding],
    architecture_metrics: list[ArchitectureMetric],
    health_score: HealthScore | None,
    specific_finding_ids: list[str] | None = None,
) -> dict[str, Any]:
    """
    Construct a structured, secret-redacted, size-capped (32-64KB) evidence pack for LLM reasoning.
    """
    # 1. Architecture summary
    total_modules = len(architecture_metrics)
    cycles = [m for m in architecture_metrics if m.circular_component_id is not None]
    cycles_by_comp: dict[int, list[str]] = {}
    for c in cycles:
        comp_id = c.circular_component_id
        if comp_id:
            cycles_by_comp.setdefault(comp_id, []).append(c.module)

    # Top 5 hubs
    sorted_hubs = sorted(
        architecture_metrics,
        key=lambda m: (m.fan_out + m.fan_in),
        reverse=True
    )[:5]
    hubs_summary = [
        {"module": m.module, "fan_in": m.fan_in, "fan_out": m.fan_out}
        for m in sorted_hubs
    ]

    arch_summary = {
        "total_modules": total_modules,
        "circular_components_count": len(cycles_by_comp),
        "circular_modules": cycles_by_comp,
        "top_coupling_hubs": hubs_summary,
    }

    # 2. Score Summary
    score_summary = {}
    if health_score:
        score_summary = {
            "overall": health_score.overall,
            "security": health_score.security,
            "architecture": health_score.architecture,
            "maintainability": health_score.maintainability,
            "performance": health_score.performance,
            "code_quality": health_score.code_quality,
            "dependencies": health_score.dependencies,
        }

    # 3. Filter and rank findings
    if specific_finding_ids:
        target_findings = [f for f in findings if f.id in set(specific_finding_ids)]
    else:
        target_findings = list(findings)

    # Sort by severity
    target_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity.lower(), 99))

    # Build findings list with capped snippets
    serialized_findings = []
    for f in target_findings:
        snippet = f.redacted_snippet or ""
        lines = snippet.splitlines()
        if len(lines) > settings.MAX_SNIPPET_LINES:
            snippet = "\n".join(lines[:settings.MAX_SNIPPET_LINES]) + "\n... [truncated]"

        serialized_findings.append({
            "id": f.id,
            "analyzer": f.analyzer,
            "category": f.category,
            "severity": f.severity,
            "rule_id": f.rule_id,
            "file_path": f.file_path,
            "start_line": f.start_line,
            "end_line": f.end_line,
            "message": f.message,
            "snippet": snippet,
        })

    # Assemble base evidence pack
    max_bytes = settings.MAX_EVIDENCE_PACK_KB * 1024

    evidence_pack: dict[str, Any] = {
        "scan_id": scan.id,
        "repository": scan.github_url,
        "commit_sha": scan.commit_sha,
        "scores": score_summary,
        "architecture": arch_summary,
        "language_summary": scan.language_stats.get("language_counts", {}) if scan.language_stats else {},
        "findings": serialized_findings,
    }

    # Redact everything
    evidence_pack = redact_dict(evidence_pack) or evidence_pack

    # Enforce size limit by trimming findings if necessary
    raw_json = json.dumps(evidence_pack)
    while len(raw_json.encode("utf-8")) > max_bytes and len(evidence_pack["findings"]) > 5:
        # Drop last (lowest priority) finding
        evidence_pack["findings"].pop()
        raw_json = json.dumps(evidence_pack)

    return evidence_pack
