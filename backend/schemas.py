"""backend/schemas.py — Pydantic request/response models."""
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, ConfigDict


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str = "developer"


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    email: EmailStr
    role: str
    is_active: bool
    created_at: datetime


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class DeploymentCreate(BaseModel):
    commit_sha: str
    service_name: str
    environment: str = "production"


class DeploymentUpdate(BaseModel):
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    security_score: Optional[int] = None
    status: Optional[str] = None
    gitleaks_findings: Optional[int] = None
    privacy_scan_findings: Optional[int] = None
    trivy_critical_count: Optional[int] = None
    opa_denials: Optional[str] = None


class DeploymentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    run_id: str
    commit_sha: str
    service_name: str
    environment: str
    risk_score: Optional[float]
    risk_level: Optional[str]
    security_score: Optional[int]
    status: str
    gitleaks_findings: int
    privacy_scan_findings: int
    trivy_critical_count: int
    created_at: datetime
    updated_at: datetime


class AuditEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    deployment_id: Optional[int]
    event_type: str
    actor: str
    detail: Optional[str]
    event_hash: str
    prev_hash: str
    timestamp: datetime
