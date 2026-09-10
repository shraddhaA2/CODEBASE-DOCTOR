import json
import shutil
import subprocess
import sys
from pathlib import Path
from app.analyzers.base import BaseAnalyzer, FindingData, extract_snippet
from app.config import settings, PROJECT_ROOT


def get_semgrep_path() -> str:
    """Find semgrep executable in current Python environment or system PATH."""
    venv_semgrep = Path(sys.executable).parent / ("semgrep.exe" if sys.platform == "win32" else "semgrep")
    if venv_semgrep.exists():
        return str(venv_semgrep)
    system_semgrep = shutil.which("semgrep")
    if system_semgrep:
        return system_semgrep
    return "semgrep"


class SemgrepAnalyzer(BaseAnalyzer):
    def run(self) -> list[FindingData]:
        findings: list[FindingData] = []

        rules_path = PROJECT_ROOT / "rules" / "semgrep" / "python.yml"
        if not rules_path.exists():
            return [self.create_error_finding(f"Semgrep rules file missing: {rules_path}")]

        # Check if Python files exist
        has_python = any(self.workspace_root.rglob("*.py"))
        if not has_python:
            return findings

        semgrep_exe = get_semgrep_path()

        cmd = [
            semgrep_exe,
            "--config", str(rules_path),
            "--json",
            "--quiet",
            "--metrics=off",
            "--disable-version-check",
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
            return [self.create_error_finding(f"Semgrep timed out after {settings.ANALYZER_TIMEOUT_SEC}s")]
        except Exception as e:
            return [self.create_error_finding(f"Failed to execute Semgrep: {e}")]

        output = result.stdout.strip()
        if not output:
            if result.stderr.strip() and result.returncode != 0:
                return [self.create_error_finding(f"Semgrep error: {result.stderr.strip()[:300]}")]
            return findings

        try:
            data = json.loads(output)
        except json.JSONDecodeError as e:
            return [self.create_error_finding(f"Invalid Semgrep JSON output: {e}", {"raw": output[:500]})]

        for item in data.get("results", []):
            rule_id = item.get("check_id", "semgrep:unknown")
            raw_path = item.get("path", "")
            try:
                rel_file = str(Path(raw_path).relative_to(self.workspace_root)).replace("\\", "/")
            except ValueError:
                rel_file = raw_path.replace("\\", "/")

            start_line = item.get("start", {}).get("line")
            end_line = item.get("end", {}).get("line", start_line)

            extra = item.get("extra", {})
            message = extra.get("message", "Semgrep security finding")
            raw_sev = extra.get("severity", "WARNING").upper()

            # Map severity
            if raw_sev == "ERROR":
                severity = "high"
                if "injection" in rule_id.lower() or "shell" in rule_id.lower() or "eval" in rule_id.lower():
                    severity = "critical"
            elif raw_sev == "WARNING":
                severity = "medium"
            else:
                severity = "low"

            snippet = extract_snippet(self.workspace_root, rel_file, start_line, end_line)
            if not snippet and extra.get("lines"):
                snippet = extra.get("lines")

            findings.append(
                FindingData(
                    analyzer="semgrep",
                    category="security",
                    severity=severity,  # type: ignore
                    rule_id=rule_id,
                    file_path=rel_file,
                    start_line=start_line,
                    end_line=end_line,
                    message=message,
                    evidence={
                        "metadata": extra.get("metadata", {}),
                        "engine": "semgrep",
                    },
                    redacted_snippet=snippet,
                )
            )

        return findings
