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


# Explicit flake8-bandit (S) rule classifications
# Aligns with Bandit's standard severity ratings:
# - S101 ('assert' used) is explicitly LOW severity (defensive constructs/test assertions)
# - Injection, exec, eval, unsafe deserialization, hardcoded passwords remain HIGH
# - Weak crypto, binding to 0.0.0.0, missing timeouts remain MEDIUM
RUFF_BANDIT_SEVERITY: dict[str, tuple[str, str]] = {
    # High-severity security vulnerabilities
    "S102": ("security", "high"),      # exec_used
    "S103": ("security", "high"),      # bad_file_permissions
    "S105": ("security", "high"),      # hardcoded_password_string
    "S106": ("security", "high"),      # hardcoded_password_funcarg
    "S107": ("security", "high"),      # hardcoded_password_default
    "S301": ("security", "high"),      # pickle
    "S302": ("security", "high"),      # marshal
    "S307": ("security", "high"),      # eval_used
    "S308": ("security", "high"),      # mark_safe
    "S501": ("security", "high"),      # request_with_no_cert_validation
    "S506": ("security", "high"),      # unsafe_yaml_load
    "S602": ("security", "high"),      # subprocess_popen_with_shell_equals_true
    "S604": ("security", "high"),      # any_other_function_with_shell_equals_true
    "S605": ("security", "high"),      # start_process_with_a_shell
    "S608": ("security", "high"),      # hardcoded_sql_expressions
    "S612": ("security", "high"),      # logging_config_listen

    # Medium-severity security issues
    "S104": ("security", "medium"),    # hardcoded_bind_all_interfaces (0.0.0.0)
    "S108": ("security", "medium"),    # hardcoded_tmp_directory (/tmp)
    "S113": ("security", "medium"),    # request_without_timeout
    "S303": ("security", "medium"),    # md5_used
    "S304": ("security", "medium"),    # insecure_cipher
    "S305": ("security", "medium"),    # insecure_hash
    "S306": ("security", "medium"),    # mktemp_q
    "S310": ("security", "medium"),    # urllib_urlopen
    "S313": ("security", "medium"),    # xml_bad_cdata
    "S314": ("security", "medium"),    # xml_bad_element_tree
    "S315": ("security", "medium"),    # xml_bad_expat_builder
    "S316": ("security", "medium"),    # xml_bad_expat_reader
    "S317": ("security", "medium"),    # xml_bad_sax
    "S318": ("security", "medium"),    # xml_bad_minidom
    "S319": ("security", "medium"),    # xml_bad_pulldom
    "S320": ("security", "medium"),    # xml_bad_etree
    "S324": ("security", "medium"),    # hashlib_insecure_hash_functions
    "S601": ("security", "medium"),    # paramiko_call
    "S609": ("security", "medium"),    # unix_wildcard_injection
    "S610": ("security", "medium"),    # django_extra_used
    "S611": ("security", "medium"),    # django_rawsql_used

    # Low-severity security issues
    # S101: In Python, assertions are standard defensive checks and test primitives.
    # Bandit officially rates B101 as LOW severity. Codebase Doctor deterministically
    # maps S101 to 'low' severity under 'security' to prevent score distortion.
    "S101": ("security", "low"),       # assert_used
    "S110": ("security", "low"),       # try_except_pass
    "S112": ("security", "low"),       # try_except_continue
    "S311": ("security", "low"),       # pseudo_random_generators
    "S603": ("security", "low"),       # subprocess_without_shell_equals_true
    "S606": ("security", "low"),       # start_process_with_no_shell
    "S607": ("security", "low"),       # start_process_with_partial_path
}


def classify_ruff_rule(rule_code: str) -> tuple[str, str]:
    """
    Deterministically map Ruff rule codes to normalized (category, severity).
    Valid categories: 'bug' | 'security' | 'dead_code' | 'dependency' | 'architecture' | 'quality'
    Valid severities: 'critical' | 'high' | 'medium' | 'low' | 'info'
    """
    code_upper = rule_code.upper()

    # 1. Flake8-Bandit security rules
    if code_upper in RUFF_BANDIT_SEVERITY:
        return RUFF_BANDIT_SEVERITY[code_upper]

    if code_upper.startswith("S"):
        # Unknown Bandit security rule: default to medium severity security
        return ("security", "medium")

    # 2. Dead code rules
    if code_upper in {"F401", "F841"}:
        return ("dead_code", "low")

    # 3. Critical runtime bugs / syntax errors
    if code_upper in {"F821", "F822", "F823", "F706"} or code_upper.startswith("E9"):
        return ("bug", "high")

    # 4. Pyflakes logic bugs
    if code_upper.startswith("F6") or code_upper.startswith("F7"):
        return ("bug", "high")
    if code_upper.startswith("F8"):
        return ("bug", "medium")
    if code_upper.startswith("F"):
        return ("quality", "medium")

    # 5. Flake8-Bugbear rules
    if code_upper.startswith("B"):
        if code_upper in {"B006", "B015", "B023"}:
            return ("bug", "medium")
        if code_upper in {"B008", "B009", "B010", "B018", "B028", "B904"}:
            return ("quality", "low")
        return ("bug", "medium")

    # 6. Async rules
    if code_upper.startswith("ASYNC"):
        return ("bug", "medium")

    # 7. Bare except
    if code_upper in {"E722", "B001"}:
        return ("quality", "medium")

    # 8. Style, formatting, comprehensions, perflint
    if code_upper.startswith("E") or code_upper.startswith("W"):
        return ("quality", "low")
    if code_upper.startswith("C4") or code_upper.startswith("PERF"):
        return ("quality", "low")

    # 9. Documented safe default for any unknown Ruff rule
    return ("quality", "low")


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

            # Deterministic Category & Severity classification
            category, severity = classify_ruff_rule(rule_code)

            snippet = extract_snippet(self.workspace_root, rel_file, start_line, end_line)

            findings.append(
                FindingData(
                    analyzer="ruff",
                    category=category,  # type: ignore
                    severity=severity,  # type: ignore
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
