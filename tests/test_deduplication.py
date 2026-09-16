import pytest
from app.analyzers.base import FindingData
from app.pipeline.deduplication import (
    deduplicate_findings,
    normalize_file_path,
    get_canonical_rule_id,
    CONFIRMED_EQUIVALENT_SECURITY_RULES,
)
from app.scoring.compute import ScoreCalculator


def test_path_normalization_equivalence():
    assert normalize_file_path("./tests/test_x.py") == "tests/test_x.py"
    assert normalize_file_path("tests/test_x.py") == "tests/test_x.py"
    assert normalize_file_path(".\\tests\\test_x.py") == "tests/test_x.py"
    assert normalize_file_path("tests\\test_x.py") == "tests/test_x.py"


def test_canonical_security_rule_mapping():
    assert get_canonical_rule_id("bandit:B101") == "bandit:B101"
    assert get_canonical_rule_id("ruff:S101") == "bandit:B101"
    assert get_canonical_rule_id("bandit:B105") == "bandit:B105"
    assert get_canonical_rule_id("ruff:S105") == "bandit:B105"
    assert get_canonical_rule_id("bandit:B113") == "bandit:B113"
    assert get_canonical_rule_id("ruff:S113") == "bandit:B113"
    assert get_canonical_rule_id("bandit:B301") == "bandit:B301"
    assert get_canonical_rule_id("ruff:S301") == "bandit:B301"

    # Non-equivalent / standalone rules map to themselves
    assert get_canonical_rule_id("ruff:E501") == "ruff:E501"
    assert get_canonical_rule_id("bandit:B403") == "bandit:B403"
    assert get_canonical_rule_id("heuristic:missing-context-manager") == "heuristic:missing-context-manager"


def test_bandit_ruff_security_deduplication_preserves_provenance():
    # Synthetic findings at same file and line
    f_bandit = FindingData(
        analyzer="bandit",
        category="security",
        severity="low",
        rule_id="bandit:B101",
        file_path="./tests/test_requests.py",
        start_line=100,
        message="Use of assert detected",
        evidence={"confidence": "HIGH"},
    )
    f_ruff = FindingData(
        analyzer="ruff",
        category="security",
        severity="low",
        rule_id="ruff:S101",
        file_path="tests/test_requests.py",
        start_line=100,
        message="Use of `assert` detected",
        evidence={"rule": "S101"},
    )

    results = deduplicate_findings([f_bandit, f_ruff])

    # Both findings must be preserved
    assert len(results) == 2

    bandit_res = next(f for f in results if f.analyzer == "bandit")
    ruff_res = next(f for f in results if f.analyzer == "ruff")

    # Bandit is canonical security owner -> Primary
    assert bandit_res.is_duplicate is False
    assert bandit_res.primary_finding_id is None
    assert bandit_res.rule_id == "bandit:B101"
    assert bandit_res.file_path == "tests/test_requests.py"
    assert bandit_res.evidence == {"confidence": "HIGH"}

    # Ruff is duplicate -> linked to primary
    assert ruff_res.is_duplicate is True
    assert ruff_res.primary_finding_id == bandit_res.id
    assert ruff_res.rule_id == "ruff:S101"
    assert ruff_res.file_path == "tests/test_requests.py"
    assert ruff_res.evidence == {"rule": "S101"}


def test_deduplicated_findings_only_penalize_once_in_scoring():
    f_bandit = FindingData(
        analyzer="bandit",
        category="security",
        severity="low",
        rule_id="bandit:B101",
        file_path="./tests/test_requests.py",
        start_line=100,
        message="Use of assert detected",
    )
    f_ruff = FindingData(
        analyzer="ruff",
        category="security",
        severity="low",
        rule_id="ruff:S101",
        file_path="tests/test_requests.py",
        start_line=100,
        message="Use of `assert` detected",
    )

    processed = deduplicate_findings([f_bandit, f_ruff])

    # Pass all processed findings to ScoreCalculator (which ignores duplicates)
    scores, breakdown = ScoreCalculator.calculate(processed)

    # Low severity penalty is -1.0. Deduplication ensures only 1 penalty (-1.0), NOT (-2.0)
    assert scores["security"] == 99.0
    assert breakdown["security"]["total_penalty"] == 1.0
    assert len(breakdown["security"]["penalties"]) == 1


def test_distinct_rules_on_same_line_not_deduplicated():
    # ruff:E501 (quality) and bandit:B101 (security) on the same line
    f_quality = FindingData(
        analyzer="ruff",
        category="quality",
        severity="low",
        rule_id="ruff:E501",
        file_path="tests/test_utils.py",
        start_line=50,
        message="Line too long (95 > 88)",
    )
    f_security = FindingData(
        analyzer="bandit",
        category="security",
        severity="low",
        rule_id="bandit:B101",
        file_path="tests/test_utils.py",
        start_line=50,
        message="Use of assert detected",
    )

    results = deduplicate_findings([f_quality, f_security])

    assert len(results) == 2
    for f in results:
        assert f.is_duplicate is False
        assert f.primary_finding_id is None

    scores, breakdown = ScoreCalculator.calculate(results)
    assert scores["code_quality"] == 99.0  # -1 for E501
    assert scores["security"] == 99.0      # -1 for B101


def test_standalone_bandit_b403_remains_unique():
    f_b403 = FindingData(
        analyzer="bandit",
        category="security",
        severity="low",
        rule_id="bandit:B403",
        file_path="tests/test_requests.py",
        start_line=8,
        message="Consider possible security implications associated with pickle module.",
    )

    results = deduplicate_findings([f_b403])
    assert len(results) == 1
    assert results[0].is_duplicate is False
    assert results[0].primary_finding_id is None

    scores, _ = ScoreCalculator.calculate(results)
    assert scores["security"] == 99.0
