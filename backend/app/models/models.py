"""
ShadowNet — SQLAlchemy ORM Models
All persistent entities stored in PostgreSQL.
"""

from sqlalchemy import (
    Column, String, Text, Integer, DateTime, Boolean, JSON,
    ForeignKey, Enum as SAEnum, Index,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base
import enum
import uuid


def gen_uuid() -> str:
    return str(uuid.uuid4())


# ─── Enums ──────────────────────────────────────────────
class UserRole(str, enum.Enum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class CaseStatus(str, enum.Enum):
    active = "active"
    archived = "archived"
    closed = "closed"


class ScanStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class TargetType(str, enum.Enum):
    email = "email"
    username = "username"
    domain = "domain"
    ip = "ip"
    phone = "phone"
    person = "person"
    organization = "organization"
    url = "url"
    file = "file"


class SeverityLevel(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


# ─── User Model ────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(255))
    role = Column(SAEnum(UserRole), default=UserRole.analyst, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    cases = relationship("Case", back_populates="owner")
    audit_logs = relationship("AuditLog", back_populates="user")


# ─── Case Model (Investigation) ────────────────────────
class Case(Base):
    __tablename__ = "cases"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    status = Column(SAEnum(CaseStatus), default=CaseStatus.active)
    priority = Column(Integer, default=0)  # 0=normal, 1=high, 2=critical
    tags = Column(JSON, default=list)
    owner_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    owner = relationship("User", back_populates="cases")
    targets = relationship("Target", back_populates="case", cascade="all, delete-orphan")


# ─── Target Model ──────────────────────────────────────
class Target(Base):
    __tablename__ = "targets"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    case_id = Column(String(36), ForeignKey("cases.id"), nullable=False)
    target_type = Column(SAEnum(TargetType), nullable=False)
    value = Column(String(500), nullable=False)  # The actual target (email, IP, etc.)
    label = Column(String(255))  # Human-readable label
    extra_data = Column(JSON, default=dict)
    neo4j_node_id = Column(String(100))  # Link to Neo4j entity
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    case = relationship("Case", back_populates="targets")
    scan_results = relationship("ScanResult", back_populates="target", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_target_case_type", "case_id", "target_type"),
    )


# ─── Scan Result Model ─────────────────────────────────
class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    target_id = Column(String(36), ForeignKey("targets.id"), nullable=False)
    module = Column(String(100), nullable=False)  # e.g. "identity.username_lookup"
    status = Column(SAEnum(ScanStatus), default=ScanStatus.pending)
    severity = Column(SAEnum(SeverityLevel), default=SeverityLevel.info)
    summary = Column(Text)
    data = Column(JSON, default=dict)  # Structured scan output
    evidence_keys = Column(JSON, default=list)  # S3/MinIO file keys
    error_message = Column(Text)
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    target = relationship("Target", back_populates="scan_results")

    __table_args__ = (
        Index("idx_scan_module_status", "module", "status"),
    )


# ─── Alert Model ───────────────────────────────────────
class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    case_id = Column(String(36), ForeignKey("cases.id"))
    title = Column(String(500), nullable=False)
    message = Column(Text)
    severity = Column(SAEnum(SeverityLevel), default=SeverityLevel.info)
    source_module = Column(String(100))
    is_read = Column(Boolean, default=False)
    data = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# ─── Audit Log Model ───────────────────────────────────
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    user_id = Column(String(36), ForeignKey("users.id"))
    action = Column(String(100), nullable=False)  # e.g. "scan.launch", "case.create"
    resource = Column(String(100))  # e.g. "case", "target"
    resource_id = Column(String(36))
    details = Column(JSON, default=dict)
    ip_address = Column(String(45))
    hmac_hash = Column(String(128))  # Tamper-proof chain
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    user = relationship("User", back_populates="audit_logs")

    __table_args__ = (
        Index("idx_audit_user_action", "user_id", "action"),
    )
