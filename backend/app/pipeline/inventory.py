import os
from pathlib import Path
from typing import Any
from app.security.workspace import assert_safe_path

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".zip", ".tar", ".gz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".whl",
    ".pyc", ".pyo", ".pyd",
    ".pdf", ".docx", ".xlsx", ".pptx",
    ".mp3", ".mp4", ".wav", ".avi",
    ".sqlite", ".db", ".sqlite3",
}

LANGUAGE_MAP = {
    ".py": "Python",
    ".pyi": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".scss": "CSS",
    ".json": "JSON",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".md": "Markdown",
    ".rst": "reStructuredText",
    ".txt": "Text",
    ".sh": "Shell",
    ".bash": "Shell",
    ".bat": "Batch",
    ".ps1": "PowerShell",
    ".sql": "SQL",
    ".toml": "TOML",
    ".ini": "INI",
    ".cfg": "Config",
}


def is_binary_file(file_path: Path) -> bool:
    if file_path.suffix.lower() in BINARY_EXTENSIONS:
        return True
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            if b"\0" in chunk:
                return True
    except Exception:
        return True
    return False


class RepositoryInventory:
    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root.resolve()

    def generate(self) -> dict[str, Any]:
        """
        Generate inventory of the cloned repository.
        Returns detailed language statistics and file lists.
        """
        files_data: list[dict[str, Any]] = []
        total_files = 0
        python_files = 0
        non_python_files = 0
        skipped_binary_files = 0
        total_size_bytes = 0
        languages: dict[str, int] = {}
        language_bytes: dict[str, int] = {}

        for root, dirs, files in os.walk(self.workspace_root):
            # Exclude .git directory
            if ".git" in dirs:
                dirs.remove(".git")

            for file in files:
                file_path = Path(root) / file
                try:
                    safe_path = assert_safe_path(self.workspace_root, file_path)
                except Exception:
                    continue

                total_files += 1
                rel_path = str(safe_path.relative_to(self.workspace_root)).replace("\\", "/")

                try:
                    size = safe_path.stat().st_size
                except OSError:
                    size = 0

                total_size_bytes += size

                if is_binary_file(safe_path):
                    skipped_binary_files += 1
                    ext = safe_path.suffix.lower() or "binary"
                    lang = "Binary"
                else:
                    ext = safe_path.suffix.lower()
                    lang = LANGUAGE_MAP.get(ext, "Other")

                languages[lang] = languages.get(lang, 0) + 1
                language_bytes[lang] = language_bytes.get(lang, 0) + size

                if lang == "Python":
                    python_files += 1
                else:
                    non_python_files += 1

                files_data.append({
                    "path": rel_path,
                    "size": size,
                    "language": lang,
                    "is_binary": lang == "Binary"
                })

        return {
            "total_files": total_files,
            "python_files": python_files,
            "non_python_files": non_python_files,
            "skipped_binary_files": skipped_binary_files,
            "total_size_bytes": total_size_bytes,
            "language_counts": languages,
            "language_bytes": language_bytes,
            "files": files_data,
        }
