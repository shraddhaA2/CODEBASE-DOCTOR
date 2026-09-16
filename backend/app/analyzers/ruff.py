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
    Valid categories: 'security' | 'dead_code' | 'architecture' | 'dependency' | 'bug' | 'quality'
    Valid severities: 'critical' | 'high' | 'medium' | 'low' | 'info'
    """
    code_upper = rule_code.upper()

    # 1. Flake8-Bandit Security rules (S followed by digits, e.g. S101, S105, S301)
    if code_upper in RUFF_BANDIT_SEVERITY:
        return RUFF_BANDIT_SEVERITY[code_upper]

    if code_upper.startswith("S") and len(code_upper) > 1 and code_upper[1].isdigit():
        # Unknown Bandit security rule: safe default to medium severity security
        return ("security", "medium")

    # 2. Dead Code rules (unused imports, variables, arguments, comments, noqa)
    if code_upper in {"F401", "F841", "F842", "B007", "RUF100"}:
        return ("dead_code", "low")
    if code_upper.startswith("ARG"):  # flake8-unused-arguments (ARG001-ARG005)
        return ("dead_code", "low")
    if code_upper.startswith("ERA"):  # eradicate commented-out code (ERA001)
        return ("dead_code", "low")

    # 3. Architecture & Import Boundaries
    if code_upper.startswith("TID"):  # flake8-tidy-imports
        if code_upper == "TID251":  # banned API
            return ("architecture", "medium")
        return ("architecture", "low")  # TID252 relative imports, TID253 banned module-level
    if code_upper.startswith("TCH"):  # flake8-type-checking imports
        return ("architecture", "low")
    if code_upper.startswith("INP"):  # flake8-no-pep420 implicit namespace packages
        return ("architecture", "low")
    if code_upper.startswith("ICN"):  # flake8-import-conventions
        return ("architecture", "low")

    # 4. Dependency rules
    if code_upper.startswith("DEP"):  # dependency specifications
        return ("dependency", "low")
    if code_upper.startswith("EXE"):  # flake8-executable (shebang & permissions)
        return ("dependency", "low")

    # 5. Bug - High Severity (Syntax errors, runtime crashes, undefined symbols)
    if code_upper in {"F821", "F822", "F823", "F706", "F701", "F702", "F704", "F707", "F621", "F622", "F831"}:
        return ("bug", "high")
    if code_upper.startswith("E9"):  # SyntaxError, IndentationError, IOError
        return ("bug", "high")
    if code_upper.startswith("F7"):  # Syntax errors in control flow
        return ("bug", "high")
    if code_upper.startswith("PLE"):  # Pylint error codes
        return ("bug", "high")

    # 6. Bug - Medium Severity (Logic bugs, race conditions, async hazards, bugbear)
    if code_upper.startswith("F6"):  # duplicate dict keys, assert tuple
        return ("bug", "medium")
    if code_upper.startswith("F8"):  # redefinition of unused name, other logic errors
        return ("bug", "medium")
    if code_upper.startswith("ASYNC"):  # flake8-async hazards
        return ("bug", "medium")
    if code_upper.startswith("PLW"):  # Pylint warnings
        return ("bug", "medium")
    if code_upper.startswith("B"):
        # Flake8-Bugbear bug rules
        if code_upper in {"B006", "B015", "B017", "B023", "B026", "B002", "B003", "B004", "B005", "B012", "B016", "B020"}:
            return ("bug", "medium")
        if code_upper == "B021":  # f-string docstring
            return ("bug", "low")
        if code_upper in {"B008", "B009", "B010", "B018", "B024", "B027", "B028", "B904", "B905"}:
            return ("quality", "low")
        if code_upper == "B001":  # bare except
            return ("quality", "medium")
        return ("bug", "medium")

    # 7. Quality - Medium Severity (bare/blind exception handling, complexity)
    if code_upper in {"E722", "BLE001"}:
        return ("quality", "medium")
    if code_upper.startswith("C9"):  # mccabe complexity (C901)
        return ("quality", "medium")

    # 8. Quality - Low Severity (formatting, lint, style, conventions, refactoring)
    if code_upper.startswith("E") or code_upper.startswith("W"):  # pycodestyle
        return ("quality", "low")
    if code_upper.startswith("N"):  # pep8-naming (N801-N818)
        return ("quality", "low")
    if code_upper.startswith("D") or code_upper.startswith("DOC"):  # pydocstyle
        return ("quality", "low")
    if code_upper.startswith("UP"):  # pyupgrade (UP001-UP043)
        return ("quality", "low")
    if code_upper.startswith("I"):  # isort (I001, I002)
        return ("quality", "low")
    if code_upper.startswith("C4"):  # flake8-comprehensions
        return ("quality", "low")
    if code_upper.startswith("SIM"):  # flake8-simplify
        return ("quality", "low")
    if code_upper.startswith("PIE"):  # flake8-pie
        return ("quality", "low")
    if code_upper.startswith("RET"):  # flake8-return
        return ("quality", "low")
    if code_upper.startswith("RSE"):  # flake8-raise
        return ("quality", "low")
    if code_upper.startswith("SLF"):  # flake8-self
        return ("quality", "low")
    if code_upper.startswith("PTH"):  # flake8-use-pathlib
        return ("quality", "low")
    if code_upper.startswith("T20"):  # flake8-print
        return ("quality", "low")
    if code_upper.startswith("Q"):  # flake8-quotes
        return ("quality", "low")
    if code_upper.startswith("COM"):  # flake8-commas
        return ("quality", "low")
    if code_upper.startswith("DTZ"):  # flake8-datetimez
        return ("quality", "low")
    if code_upper.startswith("EM"):  # flake8-errmsg
        return ("quality", "low")
    if code_upper.startswith("ISC"):  # flake8-implicit-str-concat
        return ("quality", "low")
    if code_upper.startswith("G") or code_upper.startswith("LOG"):  # logging format
        return ("quality", "low")
    if code_upper.startswith("PGH"):  # pygrep-hooks
        return ("quality", "low")
    if code_upper.startswith("PLR") or code_upper.startswith("PLC"):  # Pylint refactor / convention
        return ("quality", "low")
    if code_upper.startswith("TRY"):  # tryceratops
        return ("quality", "low")
    if code_upper.startswith("FLY"):  # flynt
        return ("quality", "low")
    if code_upper.startswith("PERF"):  # perflint
        return ("quality", "low")
    if code_upper.startswith("FURB"):  # refurb
        return ("quality", "low")
    if code_upper.startswith("ANN"):  # flake8-annotations
        return ("quality", "low")
    if code_upper.startswith("FBT"):  # flake8-boolean-trap
        return ("quality", "low")
    if code_upper.startswith("PT"):  # flake8-pytest-style
        return ("quality", "low")
    if code_upper.startswith("RUF"):  # Ruff-specific rules (except RUF100)
        return ("quality", "low")
    if code_upper.startswith("F"):  # remaining Pyflakes
        return ("quality", "low")

    # 9. Documented safe default for any unknown Ruff rule
    return ("quality", "low")


class RuffAnalyzer(BaseAnalyzer):
    default_category = "quality"
    analyzer_name = "ruff"

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
