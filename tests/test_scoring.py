import pytest
from app.analyzers.base import FindingData
from app.scoring.compute import ScoreCalculator


def test_perfect_score_when_no_findings():
    findings = []
    scores, breakdown = ScoreCalculator.calculate(findings)

    assert scores["security"] == 100.0
    assert scores["architecture"] == 100.0
    assert scores["maintainability"] == 100.0
    assert scores["performance"] == 100.0
    assert scores["code_quality"] == 100.0
    assert scores["dependencies"] == 100.0
    assert scores["overall"] == 100.0

    assert breakdown["performance"]["status"] == "neutral"
    assert "No static performance issues were detected" in breakdown["performance"]["explanation"]


def test_golden_number_score_calculation():
    # 1 Critical security finding (-15) -> security = 85.0
    # 1 High architecture finding (-8) -> architecture = 92.0
    # 1 Medium dead_code finding (-3) -> maintainability = 97.0
    # 0 performance findings -> performance = 100.0
    # 1 Low quality finding (-1) -> code_quality = 99.0
    # 1 High dependency finding (-8) -> dependencies = 92.0
    findings = [
        FindingData(
            analyzer="bandit",
            category="security",
            severity="critical",
            rule_id="bandit:B602",
            file_path="app.py",
            message="shell=True",
        ),
        FindingData(
            analyzer="architecture",
            category="architecture",
            severity="high",
            rule_id="arch:circular-dependency",
            file_path="a.py",
            message="Cycle",
        ),
        FindingData(
            analyzer="ruff",
            category="dead_code",
            severity="medium",
            rule_id="ruff:F401",
            file_path="b.py",
            message="Unused import",
        ),
        FindingData(
            analyzer="ruff",
            category="quality",
            severity="low",
            rule_id="ruff:E501",
            file_path="c.py",
            message="Line too long",
        ),
        FindingData(
            analyzer="dependencies",
            category="dependency",
            severity="high",
            rule_id="pip-audit:CVE-2023-1234",
            file_path="requirements.txt",
            message="Known vulnerability",
        ),
    ]

    scores, breakdown = ScoreCalculator.calculate(findings)

    assert scores["security"] == 85.0
    assert scores["architecture"] == 92.0
    assert scores["maintainability"] == 97.0
    assert scores["performance"] == 100.0
    assert scores["code_quality"] == 99.0
    assert scores["dependencies"] == 92.0

    # Expected overall:
    # 85*0.25 + 92*0.15 + 97*0.15 + 100*0.10 + 99*0.20 + 92*0.15
    # = 21.25 + 13.80 + 14.55 + 10.00 + 19.80 + 13.80 = 93.20
    expected_overall = round(
        85.0 * 0.25 + 92.0 * 0.15 + 97.0 * 0.15 + 100.0 * 0.10 + 99.0 * 0.20 + 92.0 * 0.15,
        1
    )
    assert scores["overall"] == expected_overall
    assert scores["overall"] == 93.2


def test_score_floor_at_zero():
    # 10 Critical security findings = 150 penalty -> must floor at 0.0
    findings = [
        FindingData(
            analyzer="semgrep",
            category="security",
            severity="critical",
            rule_id=f"rule-{i}",
            file_path="vuln.py",
            message="critical vuln",
        )
        for i in range(10)
    ]
    scores, breakdown = ScoreCalculator.calculate(findings)
    assert scores["security"] == 0.0
    assert breakdown["security"]["total_penalty"] == 150.0
    assert breakdown["security"]["final_score"] == 0.0


def test_auditable_breakdown_contains_all_fields():
    findings = [
        FindingData(
            analyzer="bandit",
            category="security",
            severity="high",
            rule_id="bandit:B101",
            file_path="test.py",
            start_line=10,
            message="assert used in production",
        )
    ]
    scores, breakdown = ScoreCalculator.calculate(findings)

    sec_breakdown = breakdown["security"]
    assert sec_breakdown["starting_score"] == 100.0
    assert sec_breakdown["total_penalty"] == 8.0
    assert sec_breakdown["final_score"] == 92.0
    assert len(sec_breakdown["penalties"]) == 1
    assert sec_breakdown["penalties"][0]["rule_id"] == "bandit:B101"
    assert sec_breakdown["penalties"][0]["penalty"] == 8.0

    assert "overall" in breakdown
    assert "formula" in breakdown["overall"]
    assert breakdown["overall"]["calculated_overall"] == scores["overall"]
