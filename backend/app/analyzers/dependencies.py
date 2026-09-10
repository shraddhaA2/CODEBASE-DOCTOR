import json
import re
import subprocess
import sys
from pathlib import Path
from app.analyzers.base import BaseAnalyzer, FindingData
from app.config import settings


class DependencyAnalyzer(BaseAnalyzer):
    def run(self) -> list[FindingData]:
        findings: list[FindingData] = []

        # Detect manifests
        manifests: list[Path] = []
        for pattern in ["*requirements*.txt", "pyproject.toml", "Pipfile", "setup.py", "setup.cfg"]:
            manifests.extend(self.workspace_root.glob(pattern))
            manifests.extend(self.workspace_root.glob(f"**/{pattern}"))

        # Deduplicate and sort
        manifest_paths = sorted(list({p for p in manifests if ".git" not in p.parts}))

        if not manifest_paths:
            # No dependencies declared
            return findings

        # Check for unpinned dependencies in requirements.txt files
        req_files = [p for p in manifest_paths if p.name.endswith(".txt") and "requirement" in p.name.lower()]
        for req_file in req_files:
            rel_path = str(req_file.relative_to(self.workspace_root)).replace("\\", "/")
            try:
                with open(req_file, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
                for idx, line in enumerate(lines, start=1):
                    raw_line = line.strip()
                    if not raw_line or raw_line.startswith("#") or raw_line.startswith("-"):
                        continue
                    # Match package name
                    pkg_match = re.match(r"^([a-zA-Z0-9_\-\.]+)(.*)$", raw_line)
                    if pkg_match:
                        pkg_name = pkg_match.group(1)
                        version_spec = pkg_match.group(2).strip()
                        if not version_spec or version_spec == "*":
                            findings.append(
                                FindingData(
                                    analyzer="dependencies",
                                    category="dependency",
                                    severity="low",
                                    rule_id="dep:unpinned-dependency",
                                    file_path=rel_path,
                                    start_line=idx,
                                    end_line=idx,
                                    message=f"Dependency '{pkg_name}' has no version pin, risking supply-chain breakage.",
                                    evidence={"package": pkg_name, "raw_spec": raw_line},
                                    redacted_snippet=raw_line,
                                )
                            )
            except Exception as e:
                findings.append(self.create_error_finding(f"Failed to read {rel_path}: {e}"))

        # Run pip-audit if requirements file exists
        if req_files:
            target_req = req_files[0]
            rel_req = str(target_req.relative_to(self.workspace_root)).replace("\\", "/")

            cmd = [
                sys.executable,
                "-m",
                "pip_audit",
                "-r",
                str(target_req),
                "-f",
                "json",
                "--desc",
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
                findings.append(self.create_error_finding(f"pip-audit timed out on {rel_req}"))
                return findings
            except Exception as e:
                findings.append(self.create_error_finding(f"Failed to execute pip-audit: {e}"))
                return findings

            audit_stdout = result.stdout.strip()
            if audit_stdout:
                try:
                    audit_data = json.loads(audit_stdout)
                    # pip-audit returns dependencies array
                    dependencies = audit_data.get("dependencies", [])
                    for dep in dependencies:
                        pkg = dep.get("name")
                        ver = dep.get("version")
                        vulns = dep.get("vulns", [])
                        for vuln in vulns:
                            cve_id = vuln.get("id", "VULN")
                            desc = vuln.get("description", "Known vulnerable dependency")
                            fix_versions = vuln.get("fix_versions", [])

                            findings.append(
                                FindingData(
                                    analyzer="dependencies",
                                    category="dependency",
                                    severity="high",
                                    rule_id=f"pip-audit:{cve_id}",
                                    file_path=rel_req,
                                    start_line=1,
                                    end_line=1,
                                    message=f"Vulnerability {cve_id} in {pkg}=={ver}: {desc[:150]}",
                                    evidence={
                                        "package": pkg,
                                        "version": ver,
                                        "cve": cve_id,
                                        "fix_versions": fix_versions,
                                    },
                                    redacted_snippet=f"{pkg}=={ver} -> fix: {fix_versions}",
                                )
                            )
                except json.JSONDecodeError:
                    if result.returncode != 0 and result.stderr.strip():
                        findings.append(
                            self.create_error_finding(
                                f"pip-audit error: {result.stderr.strip()[:200]}"
                            )
                        )

        return findings
