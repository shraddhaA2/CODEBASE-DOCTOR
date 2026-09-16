from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import settings

# For SQLite, enable check_same_thread=False
engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {},
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """Dependency for obtaining a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Initialize all database tables and ensure backward-compatible schema migration."""
    import app.models  # noqa: F401
    Base.metadata.create_all(bind=engine)

    # Safe migration for existing SQLite database to add new metadata columns
    try:
        with engine.begin() as conn:
            res = conn.execute(text("PRAGMA table_info(findings)"))
            existing_cols = {row[1] for row in res.fetchall()}
            if existing_cols:
                if "scope" not in existing_cols:
                    conn.execute(text("ALTER TABLE findings ADD COLUMN scope VARCHAR(32) DEFAULT 'source' NOT NULL"))
                if "is_duplicate" not in existing_cols:
                    conn.execute(text("ALTER TABLE findings ADD COLUMN is_duplicate BOOLEAN DEFAULT 0 NOT NULL"))
                if "primary_finding_id" not in existing_cols:
                    conn.execute(text("ALTER TABLE findings ADD COLUMN primary_finding_id VARCHAR(36) DEFAULT NULL"))
                if "canonical_rule_id" not in existing_cols:
                    conn.execute(text("ALTER TABLE findings ADD COLUMN canonical_rule_id VARCHAR(128) DEFAULT NULL"))
    except Exception:
        pass
