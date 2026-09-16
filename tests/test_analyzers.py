import json
from pathlib import Path
from unittest.mock import patch, MagicMock
import subprocess

from app.analyzers.ruff import RuffAnalyzer
from app.analyzers.bandit import BanditAnalyzer
from app.analyzers.semgrep import SemgrepAnalyzer
from app.analyzers.dependencies import DependencyAnalyzer
from app.analyzers.architecture import ArchitectureAnalyzer
from app.analyzers.heuristics import HeuristicsAnalyzer


def test_ruff_adapter_normalization(tmp_path):
    # Create a dummy python file
    (tmp_path / "app.py").write_text("import os\n", encoding="utf-8")

    ruff_json = json.dumps([
        {
            "code": "F401",
            "message": "`os` imported but unused",
            "filename": str(tmp_path / "app.py"),
            "location": {"row": 1, "column": 1},
            "end_location": {"row": 1, "column": 10},
            "fix": None,
        },
        {
            "code": "S101",
            "message": "Use of `assert` detected",
            "filename": str(tmp_path / "app.py"),
            "location": {"row": 5, "column": 1},
            "end_location": {"row": 5, "column": 10},
            "fix": None,
        }
    ])

    analyzer = RuffAnalyzer(tmp_path)
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stdout=ruff_json, stderr="")
        findings = analyzer.run()

    assert len(findings) == 2
    # F401
    f1 = findings[0]
    assert f1.analyzer == "ruff"
    assert f1.category == "dead_code"
    assert f1.severity == "low"
    assert f1.rule_id == "ruff:F401"
    assert f1.file_path == "app.py"

    # S101: assert used is deterministically low severity
    f2 = findings[1]
    assert f2.analyzer == "ruff"
    assert f2.category == "security"
    assert f2.severity == "low"
    assert f2.rule_id == "ruff:S101"


def test_ruff_s101_does_not_become_high():
    from app.analyzers.ruff import classify_ruff_rule
    category, severity = classify_ruff_rule("S101")
    assert category == "security"
    assert severity == "low"
    assert severity != "high"


def test_ruff_genuine_high_security_rules_remain_high():
    from app.analyzers.ruff import classify_ruff_rule
    # Exec, hardcoded passwords, unsafe deserialization, shell=True, SQL injection
    high_rules = ["S102", "S105", "S106", "S107", "S301", "S302", "S307", "S501", "S506", "S602", "S605", "S608"]
    for r in high_rules:
        category, severity = classify_ruff_rule(r)
        assert category == "security"
        assert severity == "high", f"Rule {r} should remain HIGH severity"


def test_ruff_severity_normalization_is_deterministic():
    from app.analyzers.ruff import classify_ruff_rule
    rules = ["S101", "S102", "S104", "F401", "F821", "B006", "E999", "E501", "UNKNOWN_CODE"]
    for r in rules:
        res1 = classify_ruff_rule(r)
        res2 = classify_ruff_rule(r)
        assert res1 == res2, f"Normalization of {r} is not deterministic"


def test_ruff_unknown_rules_use_documented_safe_default():
    from app.analyzers.ruff import classify_ruff_rule
    # Unknown S rule defaults to medium security rather than high
    s_cat, s_sev = classify_ruff_rule("S9999")
    assert s_cat == "security"
    assert s_sev == "medium"
    assert s_sev != "high"

    # Unknown generic rule defaults to low quality rather than high
    gen_cat, gen_sev = classify_ruff_rule("CUSTOM_XYZ")
    assert gen_cat == "quality"
    assert gen_sev == "low"
    assert gen_sev != "high"


def test_ruff_categories_across_all_rule_families():
    from app.analyzers.ruff import classify_ruff_rule

    # 1. Security rules
    sec_rules = {
        "S101": ("security", "low"),
        "S102": ("security", "high"),
        "S105": ("security", "high"),
        "S301": ("security", "high"),
        "S113": ("security", "medium"),
    }
    for code, (expected_cat, expected_sev) in sec_rules.items():
        cat, sev = classify_ruff_rule(code)
        assert cat == expected_cat, f"Rule {code} should be {expected_cat}, got {cat}"
        assert sev == expected_sev, f"Rule {code} should be {expected_sev}, got {sev}"

    # 2. Quality rules
    quality_rules = ["E501", "W291", "N802", "D100", "C901", "C408", "SIM101", "UP006", "B008", "B904"]
    for code in quality_rules:
        cat, sev = classify_ruff_rule(code)
        assert cat == "quality", f"Rule {code} should be quality, got {cat}"

    # 3. Bug-related rules
    bug_rules = ["F821", "F822", "E999", "F706", "B006", "B017", "ASYNC100", "PLE0100"]
    for code in bug_rules:
        cat, sev = classify_ruff_rule(code)
        assert cat == "bug", f"Rule {code} should be bug, got {cat}"

    # 4. Dead-code rules
    dead_code_rules = ["F401", "F841", "ARG001", "ERA001", "RUF100", "B007"]
    for code in dead_code_rules:
        cat, sev = classify_ruff_rule(code)
        assert cat == "dead_code", f"Rule {code} should be dead_code, got {cat}"

    # 5. Architecture rules
    arch_rules = ["TID251", "TID252", "TCH001", "INP001", "ICN001"]
    for code in arch_rules:
        cat, sev = classify_ruff_rule(code)
        assert cat == "architecture", f"Rule {code} should be architecture, got {cat}"

    # 6. Dependency rules
    dep_rules = ["EXE001", "DEP001"]
    for code in dep_rules:
        cat, sev = classify_ruff_rule(code)
        assert cat == "dependency", f"Rule {code} should be dependency, got {cat}"

    # 7. Safe default unknown rules
    cat_unk, sev_unk = classify_ruff_rule("NON_EXISTENT_RULE_XYZ")
    assert cat_unk == "quality"
    assert sev_unk == "low"



def test_bandit_adapter_normalization(tmp_path):
    (tmp_path / "test.py").write_text("import subprocess\n", encoding="utf-8")

    bandit_json = json.dumps({
        "errors": [],
        "results": [
            {
                "code": "subprocess.Popen(cmd, shell=True)\n",
                "filename": str(tmp_path / "test.py"),
                "issue_confidence": "HIGH",
                "issue_severity": "HIGH",
                "issue_text": "subprocess call with shell=True identified, security issue.",
                "line_number": 2,
                "line_range": [2],
                "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b602_subprocess_popen_with_shell_equals_true.html",
                "test_id": "B602",
                "test_name": "subprocess_popen_with_shell_equals_true"
            }
        ]
    })

    analyzer = BanditAnalyzer(tmp_path)
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stdout=bandit_json, stderr="")
        findings = analyzer.run()

    assert len(findings) == 1
    f = findings[0]
    assert f.analyzer == "bandit"
    assert f.category == "security"
    assert f.severity == "high"
    assert f.rule_id == "bandit:B602"
    assert "subprocess call with shell=True" in f.message


def test_semgrep_adapter_normalization(tmp_path):
    (tmp_path / "api.py").write_text("import pickle\n", encoding="utf-8")

    semgrep_json = json.dumps({
        "results": [
            {
                "check_id": "rules.python-unsafe-pickle",
                "path": str(tmp_path / "api.py"),
                "start": {"line": 4, "col": 1},
                "end": {"line": 4, "col": 20},
                "extra": {
                    "message": "Unsafe deserialization: pickle.load",
                    "severity": "WARNING",
                    "metadata": {"category": "security"},
                    "lines": "pickle.loads(data)"
                }
            }
        ]
    })

    analyzer = SemgrepAnalyzer(tmp_path)
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=semgrep_json, stderr="")
        findings = analyzer.run()

    assert len(findings) == 1
    f = findings[0]
    assert f.analyzer == "semgrep"
    assert f.category == "security"
    assert f.severity == "medium"
    assert f.rule_id == "rules.python-unsafe-pickle"
    assert f.start_line == 4


def test_dependency_adapter_pip_audit(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.20.0\n", encoding="utf-8")

    audit_json = json.dumps({
        "dependencies": [
            {
                "name": "requests",
                "version": "2.20.0",
                "vulns": [
                    {
                        "id": "CVE-2018-18074",
                        "description": "The Requests package before 2.20.0 sends HTTP Authorization header to unintended hosts.",
                        "fix_versions": ["2.20.0"]
                    }
                ]
            }
        ]
    })

    analyzer = DependencyAnalyzer(tmp_path)
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stdout=audit_json, stderr="")
        findings = analyzer.run()

    assert len(findings) == 1
    f = findings[0]
    assert f.analyzer == "dependencies"
    assert f.category == "dependency"
    assert f.severity == "high"
    assert "CVE-2018-18074" in f.rule_id


def test_dependency_analyzer_error_categorization(tmp_path):
    from app.scoring.compute import ScoreCalculator

    analyzer = DependencyAnalyzer(tmp_path)
    finding = analyzer.create_error_finding("pip-audit timed out on docs/requirements.txt")
    assert finding.analyzer == "dependencies"
    assert finding.category == "dependency"
    assert finding.severity == "medium"
    assert finding.rule_id == "ANALYZER_ERROR"

    # Regression check: ensure dependency error maps to Dependencies dimension, not Code Quality
    scores, breakdown = ScoreCalculator.calculate([finding])
    assert scores["code_quality"] == 100.0
    assert scores["dependencies"] == 97.0
    assert len(breakdown["dependencies"]["penalties"]) == 1
    assert breakdown["dependencies"]["penalties"][0]["penalty"] == 3.0
    assert len(breakdown["code_quality"]["penalties"]) == 0


def test_all_analyzers_error_finding_category_mapping(tmp_path):
    assert BanditAnalyzer(tmp_path).create_error_finding("err").category == "security"
    assert SemgrepAnalyzer(tmp_path).create_error_finding("err").category == "security"
    assert ArchitectureAnalyzer(tmp_path).create_error_finding("err").category == "architecture"
    assert DependencyAnalyzer(tmp_path).create_error_finding("err").category == "dependency"
    assert RuffAnalyzer(tmp_path).create_error_finding("err").category == "quality"
    assert HeuristicsAnalyzer(tmp_path).create_error_finding("err").category == "quality"

