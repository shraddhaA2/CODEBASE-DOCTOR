import asyncio
import logging
from typing import Any
from app.db import SessionLocal
from app.models import Scan, Finding, ArchitectureMetric, HealthScore
from app.pipeline.workspace import WorkspaceManager
from app.pipeline.inventory import RepositoryInventory
from app.analyzers.ruff import RuffAnalyzer
from app.analyzers.bandit import BanditAnalyzer
from app.analyzers.semgrep import SemgrepAnalyzer
from app.analyzers.dependencies import DependencyAnalyzer
from app.analyzers.architecture import ArchitectureAnalyzer
from app.analyzers.heuristics import HeuristicsAnalyzer
from app.scoring.compute import ScoreCalculator

logger = logging.getLogger("codebase_doctor.orchestrator")

# Global scan semaphore ensuring only 1 scan runs concurrently in v1
_scan_lock = asyncio.Lock()


async def enqueue_scan(scan_id: str) -> None:
    """Entry point for executing a scan in background with queue locking."""
    async with _scan_lock:
        await asyncio.to_thread(_execute_scan_sync, scan_id)


def _execute_scan_sync(scan_id: str) -> None:
    """Synchronous pipeline execution running inside thread executor."""
    db = SessionLocal()
    try:
        workspace_mgr = WorkspaceManager(scan_id)
        scan: Scan | None = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error(f"Scan {scan_id} not found in database.")
            return

        # Transition status to running
        scan.status = "running"
        db.commit()

        logger.info(f"Starting scan {scan_id} for URL: {scan.github_url}")

        # 1. Clone repository
        workspace_dir, commit_sha = workspace_mgr.clone_repository(scan.github_url)
        scan.clone_path = str(workspace_dir)
        scan.commit_sha = commit_sha
        db.commit()

        # 2. Inventory & Language stats
        inventory_gen = RepositoryInventory(workspace_dir)
        inventory_data = inventory_gen.generate()
        scan.language_stats = inventory_data
        db.commit()

        # 3. Run Analyzers (fail-soft)
        all_findings = []

        # Ruff
        try:
            ruff_findings = RuffAnalyzer(workspace_dir).run()
            all_findings.extend(ruff_findings)
        except Exception as e:
            logger.error(f"Ruff error on scan {scan_id}: {e}")
            all_findings.append(RuffAnalyzer(workspace_dir).create_error_finding(str(e)))

        # Bandit
        try:
            bandit_findings = BanditAnalyzer(workspace_dir).run()
            all_findings.extend(bandit_findings)
        except Exception as e:
            logger.error(f"Bandit error on scan {scan_id}: {e}")
            all_findings.append(BanditAnalyzer(workspace_dir).create_error_finding(str(e)))

        # Semgrep
        try:
            semgrep_findings = SemgrepAnalyzer(workspace_dir).run()
            all_findings.extend(semgrep_findings)
        except Exception as e:
            logger.error(f"Semgrep error on scan {scan_id}: {e}")
            all_findings.append(SemgrepAnalyzer(workspace_dir).create_error_finding(str(e)))

        # Dependencies
        try:
            dep_findings = DependencyAnalyzer(workspace_dir).run()
            all_findings.extend(dep_findings)
        except Exception as e:
            logger.error(f"Dependencies error on scan {scan_id}: {e}")
            all_findings.append(DependencyAnalyzer(workspace_dir).create_error_finding(str(e)))

        # Architecture & Import Graph
        arch_metrics = []
        try:
            arch_analyzer = ArchitectureAnalyzer(workspace_dir)
            arch_findings = arch_analyzer.run()
            all_findings.extend(arch_findings)
            arch_metrics = arch_analyzer.metrics_data
        except Exception as e:
            logger.error(f"Architecture error on scan {scan_id}: {e}")
            all_findings.append(ArchitectureAnalyzer(workspace_dir).create_error_finding(str(e)))

        # Custom AST Heuristics
        try:
            heuristic_findings = HeuristicsAnalyzer(workspace_dir).run()
            all_findings.extend(heuristic_findings)
        except Exception as e:
            logger.error(f"Heuristics error on scan {scan_id}: {e}")
            all_findings.append(HeuristicsAnalyzer(workspace_dir).create_error_finding(str(e)))

        # 4. Deduplicate and persist Findings
        seen_keys = set()
        for f in all_findings:
            dedup_key = (f.analyzer, f.rule_id, f.file_path, f.start_line)
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            finding_record = Finding(
                id=f.id,
                scan_id=scan_id,
                analyzer=f.analyzer,
                category=f.category,
                severity=f.severity,
                rule_id=f.rule_id,
                file_path=f.file_path,
                start_line=f.start_line,
                end_line=f.end_line,
                message=f.message,
                evidence=f.evidence,
                redacted_snippet=f.redacted_snippet,
            )
            db.add(finding_record)

        # 5. Persist Architecture Metrics
        for m in arch_metrics:
            arch_record = ArchitectureMetric(
                scan_id=scan_id,
                module=m["module"],
                fan_in=m["fan_in"],
                fan_out=m["fan_out"],
                circular_component_id=m.get("circular_component_id"),
            )
            db.add(arch_record)

        # 6. Compute & Persist Health Scores
        scores, breakdown = ScoreCalculator.calculate(all_findings, arch_metrics)
        health_record = HealthScore(
            scan_id=scan_id,
            security=scores["security"],
            architecture=scores["architecture"],
            maintainability=scores["maintainability"],
            performance=scores["performance"],
            code_quality=scores["code_quality"],
            dependencies=scores["dependencies"],
            overall=scores["overall"],
            breakdown=breakdown,
        )
        db.add(health_record)

        # 7. Complete scan successfully
        scan.status = "succeeded"
        scan.error = None
        db.commit()
        logger.info(f"Scan {scan_id} completed successfully. Overall score: {scores['overall']}")

    except Exception as e:
        logger.exception(f"Fatal error during scan {scan_id}: {e}")
        db.rollback()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = "failed"
                scan.error = str(e)
                db.commit()
        except Exception:
            pass
    finally:
        db.close()
