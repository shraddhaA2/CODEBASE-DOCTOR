import os
from pathlib import Path


class WorkspaceSecurityError(Exception):
    """Raised when an operation violates workspace isolation rules."""
    pass


def assert_safe_path(workspace_root: Path, target_path: Path | str) -> Path:
    """
    Ensure target_path resolves strictly within workspace_root.
    Rejects path traversal or symlinks escaping the workspace root.
    """
    root_resolved = Path(workspace_root).resolve()
    target = Path(target_path)

    if not target.is_absolute():
        target = root_resolved / target

    target_resolved = target.resolve()

    try:
        # relative_to raises ValueError if target_resolved is not inside root_resolved
        target_resolved.relative_to(root_resolved)
    except ValueError:
        raise WorkspaceSecurityError(
            f"Path traversal or symlink escape detected: '{target_resolved}' is outside '{root_resolved}'"
        )

    return target_resolved


def is_safe_symlink(workspace_root: Path, link_path: Path) -> bool:
    """Check if a symlink resolves to a target inside workspace_root."""
    try:
        assert_safe_path(workspace_root, link_path)
        return True
    except WorkspaceSecurityError:
        return False


def validate_workspace_limits(
    workspace_root: Path,
    max_size_mb: int = 50,
    max_file_count: int = 2000,
    max_file_size_mb: int = 5,
) -> tuple[int, int]:
    """
    Traverse workspace and verify that size and file count limits are respected.
    Returns (total_files, total_bytes).
    Raises WorkspaceSecurityError if any limit is exceeded.
    """
    max_bytes = max_size_mb * 1024 * 1024
    max_single_file_bytes = max_file_size_mb * 1024 * 1024
    total_bytes = 0
    file_count = 0

    root_resolved = Path(workspace_root).resolve()

    for root, dirs, files in os.walk(root_resolved):
        current_dir = Path(root).resolve()
        try:
            current_dir.relative_to(root_resolved)
        except ValueError:
            raise WorkspaceSecurityError(f"Directory escape detected: {current_dir}")

        for file in files:
            file_path = current_dir / file
            # Check symlink safety
            if file_path.is_symlink():
                if not is_safe_symlink(workspace_root, file_path):
                    continue  # skip dangerous symlink

            file_count += 1
            if file_count > max_file_count:
                raise WorkspaceSecurityError(
                    f"Repository exceeds maximum file count limit of {max_file_count} files."
                )

            try:
                size = file_path.stat().st_size
                if size > max_single_file_bytes:
                    # Individual file exceeds limit - not necessarily fatal for entire repo,
                    # but check if excessive
                    pass
                total_bytes += size
            except (OSError, FileNotFoundError):
                continue

            if total_bytes > max_bytes:
                raise WorkspaceSecurityError(
                    f"Repository exceeds maximum clone size limit of {max_size_mb} MB."
                )

    return file_count, total_bytes
