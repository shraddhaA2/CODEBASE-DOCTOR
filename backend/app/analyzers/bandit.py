import json
import subprocess
import sys
from pathlib import Path
from app.analyzers.base import BaseAnalyzer, FindingData, extract_snippet
from app.config import settings


class BanditAnalyzer(BaseAnalyzer):
    default_category = "security"
    analyzer_name = "bandit"

    def run(self) -> list[FindingData]:
        findings: list[FindingData] = []

        # Check if Python files exist
        has_python = any(self.workspace_root.rglob("*.py"))
        if not has_python:
            return findings

        cmd = [
            sys.executable,
            "-m",
            "bandit",
            "-r",
            ".",
            "-f",
            "json",
            "-q",
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
            return [self.create_error_finding(f"Bandit timed out after {settings.ANALYZER_TIMEOUT_SEC}s")]
        except Exception as e:
            return [self.create_error_finding(f"Failed to execute Bandit: {e}")]

        output = result.stdout.strip()
        if not output:
            # Check stderr for crashes
            if result.stderr.strip():
                return [self.create_error_finding(f"Bandit crashed: {result.stderr.strip()[:300]}")]
            return findings

        try:
            data = json.loads(output)
        except json.JSONDecodeError as e:
            return [self.create_error_finding(f"Invalid Bandit JSON: {e}", {"raw": output[:500]})]

        # Check for errors reported by bandit
        if data.get("errors"):
            for err in data["errors"]:
                findings.append(
                    self.create_error_finding(f"Bandit scan error on {err.get('filename')}: {err.get('reason')}")
                )

        results = data.get("results", [])
        for item in results:
            raw_sev = item.get("issue_severity", "LOW").lower()
            if raw_sev not in {"critical", "high", "medium", "low", "info"}:
                raw_sev = "medium"

            raw_file = item.get("filename", "")
            try:
                rel_file = str(Path(raw_file).relative_to(self.workspace_root)).replace("\\", "/")
            except ValueError:
                rel_file = raw_file.replace("\\", "/")

            start_line = item.get("line_number")
            line_range = item.get("line_range", [start_line])
            end_line = max(line_range) if line_range else start_line

            snippet = extract_snippet(self.workspace_root, rel_file, start_line, end_line)
            if not snippet and item.get("code"):
                snippet = item.get("code")

            findings.append(
                FindingData(
                    analyzer="bandit",
                    category="security",
                    severity=raw_sev,  # type: ignore
                    rule_id=f"bandit:{item.get('test_id', 'UNKNOWN')}",
                    file_path=rel_file,
                    start_line=start_line,
                    end_line=end_line,
                    message=item.get("issue_text", "Security finding detected by Bandit"),
                    evidence={
                        "test_name": item.get("test_name"),
                        "confidence": item.get("issue_confidence"),
                        "more_info": item.get("more_info"),
                    },
                    redacted_snippet=snippet,
                )
            )

        return findings
