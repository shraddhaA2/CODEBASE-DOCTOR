import os
import shutil
import stat
import subprocess
from pathlib import Path
from app.config import settings
from app.security.workspace import assert_safe_path, validate_workspace_limits, WorkspaceSecurityError


def _handle_remove_readonly(func, path, exc_info):
    """Clear readonly bit and retry deletion (Windows git pack files)."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


class WorkspaceManager:
    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.workspace_dir = (settings.WORKSPACES_DIR / scan_id).resolve()

    def create_workspace(self) -> Path:
        """Create clean workspace directory."""
        if self.workspace_dir.exists():
            self.cleanup()
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        return self.workspace_dir

    def clone_repository(self, github_url: str) -> tuple[Path, str]:
        """
        Shallow clone repository with safety controls.
        Returns (workspace_dir, commit_sha).
        """
        self.create_workspace()

        cmd = [
            "git",
            "clone",
            "--depth", "1",
            "--config", "core.symlinks=false",  # disable symlink resolution during checkout on windows
            github_url,
            str(self.workspace_dir)
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=settings.CLONE_TIMEOUT_SEC,
                shell=False,
                check=False,
            )
        except subprocess.TimeoutExpired:
            self.cleanup()
            raise WorkspaceSecurityError(f"Clone timed out after {settings.CLONE_TIMEOUT_SEC} seconds.")
        except Exception as e:
            self.cleanup()
            raise WorkspaceSecurityError(f"Failed to execute git clone: {e}")

        if result.returncode != 0:
            err = result.stderr.strip() or result.stdout.strip() or "Unknown clone failure."
            self.cleanup()
            raise WorkspaceSecurityError(f"Git clone failed: {err}")

        # Extract commit SHA
        commit_sha = "unknown"
        try:
            sha_result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=str(self.workspace_dir),
                capture_output=True,
                text=True,
                timeout=10,
                shell=False,
            )
            if sha_result.returncode == 0:
                commit_sha = sha_result.stdout.strip()
        except Exception:
            pass

        # Validate limits
        validate_workspace_limits(
            self.workspace_dir,
            max_size_mb=settings.MAX_CLONE_SIZE_MB,
            max_file_count=settings.MAX_FILE_COUNT,
            max_file_size_mb=settings.MAX_FILE_SIZE_MB,
        )

        return self.workspace_dir, commit_sha

    def cleanup(self) -> None:
        """Safely delete workspace directory."""
        if self.workspace_dir.exists():
            try:
                shutil.rmtree(self.workspace_dir, onerror=_handle_remove_readonly)
            except Exception:
                pass
