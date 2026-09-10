import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from project root or current working dir
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent.parent
PROJECT_ROOT = BASE_DIR
DATA_DIR = PROJECT_ROOT / "data"
WORKSPACES_DIR = DATA_DIR / "workspaces"

# Ensure data directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
WORKSPACES_DIR.mkdir(parents=True, exist_ok=True)

class Settings:
    PROJECT_ROOT: Path = PROJECT_ROOT
    DATA_DIR: Path = DATA_DIR
    WORKSPACES_DIR: Path = WORKSPACES_DIR

    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{DATA_DIR / 'codebase_doctor.db'}")
    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", "8000"))
    
    # CORS
    raw_cors = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000")
    CORS_ORIGINS: list[str] = [origin.strip() for origin in raw_cors.split(",") if origin.strip()]

    # LLM Settings
    LLM_BASE_URL: str | None = os.getenv("LLM_BASE_URL") or None
    LLM_API_KEY: str | None = os.getenv("LLM_API_KEY") or None
    LLM_MODEL: str = os.getenv("LLM_MODEL", "gpt-4o-mini")

    # Clone & Analysis Limits
    MAX_CLONE_SIZE_MB: int = int(os.getenv("MAX_CLONE_SIZE_MB", "50"))
    MAX_FILE_COUNT: int = int(os.getenv("MAX_FILE_COUNT", "2000"))
    MAX_FILE_SIZE_MB: int = int(os.getenv("MAX_FILE_SIZE_MB", "5"))
    CLONE_TIMEOUT_SEC: int = int(os.getenv("CLONE_TIMEOUT_SEC", "60"))
    ANALYZER_TIMEOUT_SEC: int = int(os.getenv("ANALYZER_TIMEOUT_SEC", "60"))

    # Evidence pack size cap
    MAX_EVIDENCE_PACK_KB: int = 64
    MAX_SNIPPET_LINES: int = 20

settings = Settings()
