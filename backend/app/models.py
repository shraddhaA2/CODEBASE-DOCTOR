import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Text,
    DateTime,
    ForeignKey,
    JSON,
)
from sqlalchemy.orm import relationship
from app.db import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    github_url = Column(String(512), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="queued", index=True)  # queued, running, succeeded, failed
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    clone_path = Column(String(512), nullable=True)
    limits = Column(JSON, nullable=True)
    commit_sha = Column(String(64), nullable=True)
    language_stats = Column(JSON, nullable=True)

    # Relationships
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    architecture_metrics = relationship("ArchitectureMetric", back_populates="scan", cascade="all, delete-orphan")
    health_score = relationship("HealthScore", back_populates="scan", uselist=False, cascade="all, delete-orphan")
    ai_reports = relationship("AiReport", back_populates="scan", cascade="all, delete-orphan")
    patch_proposals = relationship("PatchProposal", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    analyzer = Column(String(64), nullable=False, index=True)  # ruff, bandit, semgrep, dependencies, architecture, heuristics
    category = Column(String(64), nullable=False, index=True)  # bug, security, dead_code, dependency, architecture, quality
    severity = Column(String(32), nullable=False, index=True)  # critical, high, medium, low, info
    rule_id = Column(String(128), nullable=False)
    file_path = Column(String(512), nullable=False)
    start_line = Column(Integer, nullable=True)
    end_line = Column(Integer, nullable=True)
    message = Column(Text, nullable=False)
    evidence = Column(JSON, nullable=True)
    redacted_snippet = Column(Text, nullable=True)

    scan = relationship("Scan", back_populates="findings")


class ArchitectureMetric(Base):
    __tablename__ = "architecture_metrics"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    module = Column(String(256), nullable=False)
    fan_in = Column(Integer, default=0, nullable=False)
    fan_out = Column(Integer, default=0, nullable=False)
    circular_component_id = Column(Integer, nullable=True)

    scan = relationship("Scan", back_populates="architecture_metrics")


class HealthScore(Base):
    __tablename__ = "health_scores"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True)
    security = Column(Float, nullable=False)
    architecture = Column(Float, nullable=False)
    maintainability = Column(Float, nullable=False)
    performance = Column(Float, nullable=False)
    code_quality = Column(Float, nullable=False)
    dependencies = Column(Float, nullable=False)
    overall = Column(Float, nullable=False)
    breakdown = Column(JSON, nullable=False)

    scan = relationship("Scan", back_populates="health_score")


class AiReport(Base):
    __tablename__ = "ai_reports"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    kind = Column(String(32), nullable=False)  # diagnosis, recommendations, patch
    raw_model = Column(Text, nullable=True)
    validated_json = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    scan = relationship("Scan", back_populates="ai_reports")


class PatchProposal(Base):
    __tablename__ = "patch_proposals"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    file_path = Column(String(512), nullable=False)
    original = Column(Text, nullable=False)
    proposed = Column(Text, nullable=False)
    unified_diff = Column(Text, nullable=False)
    explanation = Column(Text, nullable=False)
    confidence = Column(Float, nullable=False)
    risk = Column(String(32), nullable=False)  # low, medium, high
    status = Column(String(32), default="proposed", nullable=False)  # proposed

    scan = relationship("Scan", back_populates="patch_proposals")
