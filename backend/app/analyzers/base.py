from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal
import uuid

from app.security.redact import redact_text, redact_dict


@dataclass
class FindingData:
    analyzer: str
    category: Literal["bug", "security", "dead_code", "dependency", "architecture", "quality"]
    severity: Literal["critical", "high", "medium", "low", "info"]
    rule_id: str
    file_path: str
    message: str
    start_line: int | None = None
    end_line: int | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    redacted_snippet: str | None = None
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "analyzer": self.analyzer,
            "category": self.category,
            "severity": self.severity,
            "rule_id": self.rule_id,
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "message": redact_text(self.message) or self.message,
            "evidence": redact_dict(self.evidence),
            "redacted_snippet": redact_text(self.redacted_snippet),
        }


def extract_snippet(
    workspace_root: Path,
    file_path: str,
    start_line: int | None,
    end_line: int | None,
    context_lines: int = 3,
    max_lines: int = 20,
) -> str | None:
    """Safely extract lines from a workspace file and redact secrets."""
    if not start_line or start_line < 1:
        return None

    full_path = (workspace_root / file_path).resolve()
    try:
        full_path.relative_to(workspace_root.resolve())
    except ValueError:
        return None

    if not full_path.is_file():
        return None

    try:
        with open(full_path, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()

        total = len(all_lines)
        if start_line > total:
            return None

        actual_end = end_line if end_line and end_line >= start_line else start_line
        from_idx = max(0, start_line - 1 - context_lines)
        to_idx = min(total, actual_end + context_lines)

        snippet_lines = all_lines[from_idx:to_idx]
        if len(snippet_lines) > max_lines:
            snippet_lines = snippet_lines[:max_lines] + ["... (truncated)\n"]

        raw_snippet = "".join(snippet_lines)
        return redact_text(raw_snippet)
    except Exception:
        return None


class BaseAnalyzer(ABC):
    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root.resolve()

    @abstractmethod
    def run(self) -> list[FindingData]:
        """Execute analyzer and return list of normalized findings."""
        pass

    def create_error_finding(self, message: str, details: dict[str, Any] | None = None) -> FindingData:
        """Helper to create fail-soft analyzer_error finding."""
        return FindingData(
            analyzer=self.__class__.__name__.lower().replace("analyzer", ""),
            category="quality",
            severity="medium",
            rule_id="ANALYZER_ERROR",
            file_path=".",
            start_line=None,
            end_line=None,
            message=f"Analyzer error: {message}",
            evidence=details or {},
            redacted_snippet=None,
        )
