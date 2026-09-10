import ast
from pathlib import Path
import pytest

from app.analyzers.ruff import RuffAnalyzer
from app.analyzers.bandit import BanditAnalyzer
from app.analyzers.architecture import ArchitectureAnalyzer
from app.analyzers.heuristics import HeuristicsAnalyzer
from app.pipeline.inventory import RepositoryInventory
from app.scoring.compute import ScoreCalculator


def test_fixture_repository_pipeline_analysis(tmp_path):
    """
    Test static analysis analyzers against a fixture repository with known issues:
    - unused imports
    - shell=True
    - circular imports
    - broad exception
    Verify findings and score penalties without executing repository code.
    """
    # 1. Create fixture files
    mod_a = tmp_path / "module_a.py"
    mod_a.write_text(
        "import sys\n"
        "import module_b\n"
        "import subprocess\n\n"
        "def run_cmd(user_arg):\n"
        "    subprocess.call(user_arg, shell=True)\n",
        encoding="utf-8"
    )

    mod_b = tmp_path / "module_b.py"
    mod_b.write_text(
        "import module_a\n\n"
        "def safe_worker():\n"
        "    try:\n"
        "        pass\n"
        "    except Exception:\n"
        "        pass\n",
        encoding="utf-8"
    )

    # 2. Inventory check
    inventory = RepositoryInventory(tmp_path).generate()
    assert inventory["total_files"] == 2
    assert inventory["python_files"] == 2
    assert inventory["skipped_binary_files"] == 0

    # 3. Architecture Analyzer
    arch_analyzer = ArchitectureAnalyzer(tmp_path)
    arch_findings = arch_analyzer.run()
    # Should detect circular dependency between module_a and module_b
    assert any("circular" in f.rule_id.lower() or "cycle" in f.message.lower() for f in arch_findings)
    assert any(m["circular_component_id"] is not None for m in arch_analyzer.metrics_data)

    # 4. Custom AST Heuristics
    heuristic_analyzer = HeuristicsAnalyzer(tmp_path)
    heuristic_findings = heuristic_analyzer.run()
    # Should detect broad exception suppression in module_b.py
    assert any("broad-exception-suppression" in f.rule_id for f in heuristic_findings)

    # 5. Bandit Analyzer (real execution of bandit against fixture directory)
    bandit_analyzer = BanditAnalyzer(tmp_path)
    bandit_findings = bandit_analyzer.run()
    # Should detect shell=True (B602/B603)
    assert any("B602" in f.rule_id or "B603" in f.rule_id or "shell=True" in f.message for f in bandit_findings)

    # 6. Ruff Analyzer (real execution of ruff against fixture directory)
    ruff_analyzer = RuffAnalyzer(tmp_path)
    ruff_findings = ruff_analyzer.run()
    # Should detect unused import (F401)
    assert any("F401" in f.rule_id for f in ruff_findings)

    # 7. Compute Health Score
    all_findings = arch_findings + heuristic_findings + bandit_findings + ruff_findings
    scores, breakdown = ScoreCalculator.calculate(all_findings, arch_analyzer.metrics_data)

    assert scores["overall"] < 100.0
    assert scores["security"] < 100.0  # bandit found shell=True
    assert scores["architecture"] < 100.0  # circular dependency found
    assert scores["code_quality"] < 100.0  # broad exception or ruff issues
    assert scores["maintainability"] < 100.0  # unused import F401
    assert scores["performance"] == 100.0  # neutral performance
