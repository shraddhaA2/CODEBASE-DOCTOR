import json
import shutil
import subprocess
import sys
from pathlib import Path
from app.analyzers.base import BaseAnalyzer, FindingData, extract_snippet
from app.config import settings


def get_ruff_path() -> str:
    """Find ruff executable in current Python environment or system PATH."""
    venv_ruff = Path(sys.executable).parent / ("ruff.exe" if sys.platform == "win32" else "ruff")
    if venv_ruff.exists():
        return str(venv_ruff)
    system_ruff = shutil.which("ruff")
    if system_ruff:
        return system_ruff
    return "ruff"


class RuffAnalyzer(BaseAnalyzer):
    def run(self) -> list[FindingData]:
        findings: list[FindingData] = []
        ruff_exe = get_ruff_path()

        # Check if Python files exist
        has_python = any(self.workspace_root.rglob("*.py"))
        if not has_python:
            return findings

        cmd = [
            ruff_exe,
            "check",
            "--output-format", "json",
            "--select", "E,W,F,B,S,C4,ASYNC",  # select standard errors, warnings, pyflakes, bugbear, bandit-rules
            ".",
        ]

        try:
            result = subprocess.run(
                cmd,
                cwd=str(self.workspace_root),
                capture_output=True,
                text=True,
                timeout=settings.ANALYZER_TIMEOUT_SEC,
                shell=False,
            )
        except subprocess.TimeoutExpired:
            return [self.create_error_finding(f"Ruff timed out after {settings.ANALYZER_TIMEOUT_SEC}s")]
        except Exception as e:
            return [self.create_error_finding(f"Failed to execute Ruff: {e}")]

        # Ruff exit code: 0 = clean, 1 = issues found, >1 = syntax/crash error
        if result.returncode > 1 and not result.stdout:
            err = result.stderr.strip() or "Ruff execution failed"
            return [self.create_error_finding(err)]

        output = result.stdout.strip()
        if not output:
            return findings

        try:
            data = json.loads(output)
        except json.JSONDecodeError as e:
            return [self.create_error_finding(f"Invalid Ruff JSON output: {e}", {"raw": output[:500]})]

        for item in data:
            rule_code = item.get("code", "RUFF_ERR")
            filename = item.get("filename", "")
            try:
                rel_file = str(Path(filename).relative_to(self.workspace_root)).replace("\\", "/")
            except ValueError:
                rel_file = filename.replace("\\", "/")

            start_line = item.get("location", {}).get("row")
            end_line = item.get("end_location", {}).get("row", start_line)
            message = item.get("message", "Ruff issue detected")

            # Category & Severity mapping
            category = "quality"
            severity = "low"

            if rule_code.startswith("S"):  # Security
                category = "security"
                severity = "high"
            elif rule_code in {"F401", "F841"}:  # Unused import/var
                category = "dead_code"
                severity = "low"
            elif rule_code.startswith("B"):  # Bugbear
                category = "bug"
                severity = "medium"
            elif rule_code.startswith("E9") or rule_code.startswith("F6") or rule_code.startswith("F7") or rule_code.startswith("F8"):
                category = "bug"
                severity = "high"

            snippet = extract_snippet(self.workspace_root, rel_file, start_line, end_line)

            findings.append(
                FindingData(
                    analyzer="ruff",
                    category=category,
                    severity=severity,
                    rule_id=f"ruff:{rule_code}",
                    file_path=rel_file,
                    start_line=start_line,
                    end_line=end_line,
                    message=message,
                    evidence={"rule": rule_code, "fix": item.get("fix")},
                    redacted_snippet=snippet,
                )
            )

        return findings
