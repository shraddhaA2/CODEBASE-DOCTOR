import re
from pathlib import PurePosixPath
from typing import Literal

FileScope = Literal["source", "test", "generated", "vendor", "docs"]

TEST_DIR_NAMES = {"tests", "test", "testing", "__tests__"}
DOCS_DIR_NAMES = {"docs", "doc", "documentation"}
GENERATED_DIR_NAMES = {"generated", ".generated", "build", "dist", "target", "out"}
VENDOR_DIR_NAMES = {"vendor", "third_party", "node_modules", "site-packages", "bundled"}

TEST_FILE_PATTERNS = [
    re.compile(r"^test_.*\.py$", re.IGNORECASE),
    re.compile(r"^.*_test\.py$", re.IGNORECASE),
    re.compile(r"^conftest\.py$", re.IGNORECASE),
    re.compile(r"^tests?\.py$", re.IGNORECASE),
    re.compile(r"^.*\.test\.[jt]sx?$", re.IGNORECASE),
    re.compile(r"^.*\.spec\.[jt]sx?$", re.IGNORECASE),
]

GENERATED_FILE_PATTERNS = [
    re.compile(r"^.*_pb2\.py$", re.IGNORECASE),
    re.compile(r"^.*_pb2_grpc\.py$", re.IGNORECASE),
    re.compile(r"^.*\.min\.(js|css)$", re.IGNORECASE),
    re.compile(r"^.*\.(bundle|chunk)\.js$", re.IGNORECASE),
]

DOCS_EXTENSIONS = {".rst", ".md", ".markdown", ".adoc"}


def normalize_scope_path(file_path: str) -> str:
    """Normalize path separators to forward slashes and strip leading ./ or /."""
    p = file_path.replace("\\", "/").strip()
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def classify_file_scope(file_path: str) -> FileScope:
    """
    Deterministically classify a relative or absolute file path into one of:
    - 'test': test files, test fixtures, test directories
    - 'docs': documentation directories and documentation files
    - 'generated': build artifacts, code generation outputs (e.g. protobuf)
    - 'vendor': third-party / vendored code and dependencies
    - 'source': production application and library code (default)
    """
    if not file_path or file_path == ".":
        return "source"

    norm_path = normalize_scope_path(file_path)
    if not norm_path:
        return "source"

    pure = PurePosixPath(norm_path)
    parts = [part.lower() for part in pure.parts]
    filename = pure.name.lower()
    suffix = pure.suffix.lower()

    # 1. Directory checks across any path component
    # Test directories (any directory named tests, test, testing, etc.)
    if any(p in TEST_DIR_NAMES for p in parts[:-1]):
        return "test"

    # Vendor directories
    if any(p in VENDOR_DIR_NAMES for p in parts[:-1]):
        return "vendor"

    # Generated directories
    if any(p in GENERATED_DIR_NAMES for p in parts[:-1]):
        return "generated"

    # Documentation directories
    if any(p in DOCS_DIR_NAMES for p in parts[:-1]):
        return "docs"

    # 2. Filename-based checks
    for pattern in TEST_FILE_PATTERNS:
        if pattern.match(filename):
            return "test"

    for pattern in GENERATED_FILE_PATTERNS:
        if pattern.match(filename):
            return "generated"

    # 3. Documentation file extensions (if inside a subdirectory or recognized doc file)
    if suffix in DOCS_EXTENSIONS:
        if len(parts) > 1 or "readme" in filename or "changelog" in filename or "license" in filename:
            return "docs"

    # 4. Default to source
    return "source"
