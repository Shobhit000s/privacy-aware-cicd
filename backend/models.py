"""backend/models.py — persistent storage for users, deployments, and audit records."""
import enum
from datetime import datetime

from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, ForeignKey, Enum, Text
from sqlalchemy.orm import relationship

from database import Base


class Role(str, enum.Enum):
    ADMIN = "admin"
    SECURITY_REVIEWER = "security_reviewer"
    DEVELOPER = "developer"
    VIEWER = "viewer"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(128), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(Role), default=Role.DEVELOPER, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    deployments = relationship("Deployment", back_populates="requested_by")


class Deployment(Base):
    __tablename__ = "deployments"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(String(64), unique=True, index=True, nullable=False)
    commit_sha = Column(String(64), nullable=False)
    service_name = Column(String(128), nullable=False)
    environment = Column(String(32), default="production")
    risk_score = Column(Float, nullable=True)
    risk_level = Column(String(16), nullable=True)
    security_score = Column(Integer, nullable=True)
    status = Column(String(32), default="pending")  # pending, passed, blocked, deployed, failed
    gitleaks_findings = Column(Integer, default=0)
    privacy_scan_findings = Column(Integer, default=0)
    trivy_critical_count = Column(Integer, default=0)
    opa_denials = Column(Text, nullable=True)  # JSON-encoded list of denial messages
    requested_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    requested_by = relationship("User", back_populates="deployments")
    audit_events = relationship("AuditEvent", back_populates="deployment")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, index=True)
    deployment_id = Column(Integer, ForeignKey("deployments.id"), nullable=True)
    event_type = Column(String(64), nullable=False)  # e.g. "secret_scan", "policy_check", "deploy"
    actor = Column(String(64), nullable=False)
    detail = Column(Text, nullable=True)
    event_hash = Column(String(64), nullable=False)
    prev_hash = Column(String(64), nullable=False)
    timestamp = Column(DateTime, nullable=False)

    deployment = relationship("Deployment", back_populates="audit_events")


class SecretRotationRecord(Base):
    __tablename__ = "secret_rotations"

    id = Column(Integer, primary_key=True, index=True)
    secret_path = Column(String(256), nullable=False)
    rotation_id = Column(String(32), nullable=False)
    triggered_by_file = Column(String(256), nullable=True)
    status = Column(String(32), default="success")
    rotated_at = Column(DateTime, default=datetime.utcnow)
