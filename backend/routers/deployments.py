"""
backend/routers/deployments.py

This is the "actual business application" the pipeline deploys against:
a REST API that CI stages call to register a deployment and post scan
results, and that the dashboard/frontend queries to render compliance data.
Also doubles as the audit trail's structured source of truth (paired with
the hash-chained JSONL log for tamper-evidence — see audit.py).
"""
import hashlib
import json
import secrets as py_secrets
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

import models
import schemas
from database import get_db
from auth import get_current_user, require_role

router = APIRouter(prefix="/api/deployments", tags=["deployments"])


def _last_hash(db: Session) -> str:
    last = db.query(models.AuditEvent).order_by(models.AuditEvent.id.desc()).first()
    return last.event_hash if last else "0" * 64


def _write_audit_event(db: Session, deployment_id: Optional[int], event_type: str, actor: str, detail: dict):
    prev_hash = _last_hash(db)
    ts = datetime.utcnow()
    body = {
        "deployment_id": deployment_id,
        "event_type": event_type,
        "actor": actor,
        "detail": json.dumps(detail, default=str),
        "prev_hash": prev_hash,
        "timestamp": ts.isoformat(),
    }
    event_hash = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
    event = models.AuditEvent(
        deployment_id=deployment_id, event_type=event_type, actor=actor,
        detail=body["detail"], event_hash=event_hash, prev_hash=prev_hash, timestamp=ts,
    )
    db.add(event)
    db.commit()
    return event


@router.post("", response_model=schemas.DeploymentOut, status_code=201)
def create_deployment(
    payload: schemas.DeploymentCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    run_id = f"run-{py_secrets.token_hex(6)}"
    dep = models.Deployment(
        run_id=run_id,
        commit_sha=payload.commit_sha,
        service_name=payload.service_name,
        environment=payload.environment,
        requested_by_id=user.id,
    )
    db.add(dep)
    db.commit()
    db.refresh(dep)
    _write_audit_event(db, dep.id, "deployment_created", user.username, {"commit": payload.commit_sha})
    return dep


@router.patch("/{run_id}", response_model=schemas.DeploymentOut)
def update_deployment(
    run_id: str,
    payload: schemas.DeploymentUpdate,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    dep = db.query(models.Deployment).filter(models.Deployment.run_id == run_id).first()
    if not dep:
        raise HTTPException(status_code=404, detail="Deployment not found")

    updates = payload.model_dump(exclude_unset=True)
    for k, v in updates.items():
        setattr(dep, k, v)
    dep.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(dep)
    _write_audit_event(db, dep.id, "deployment_updated", user.username, updates)
    return dep


@router.post("/{run_id}/approve", response_model=schemas.DeploymentOut)
def approve_deployment(
    run_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_role("admin", "security_reviewer")),
):
    """Manual override gate for HIGH/CRITICAL risk deployments — restricted
    to admin / security_reviewer roles (RBAC), demonstrating the pipeline
    isn't purely automatic once risk crosses the auto-block threshold."""
    dep = db.query(models.Deployment).filter(models.Deployment.run_id == run_id).first()
    if not dep:
        raise HTTPException(status_code=404, detail="Deployment not found")
    dep.status = "approved_override"
    db.commit()
    db.refresh(dep)
    _write_audit_event(db, dep.id, "manual_approval_override", user.username,
                        {"previous_risk_level": dep.risk_level})
    return dep


@router.get("", response_model=List[schemas.DeploymentOut])
def list_deployments(
    status_filter: Optional[str] = Query(None, alias="status"),
    limit: int = 50,
    db: Session = Depends(get_db),
):
    q = db.query(models.Deployment).order_by(models.Deployment.created_at.desc())
    if status_filter:
        q = q.filter(models.Deployment.status == status_filter)
    return q.limit(limit).all()


@router.get("/{run_id}", response_model=schemas.DeploymentOut)
def get_deployment(run_id: str, db: Session = Depends(get_db)):
    dep = db.query(models.Deployment).filter(models.Deployment.run_id == run_id).first()
    if not dep:
        raise HTTPException(status_code=404, detail="Deployment not found")
    return dep


@router.get("/stats/summary")
def deployment_stats(db: Session = Depends(get_db)):
    deployments = db.query(models.Deployment).all()
    if not deployments:
        return {"total": 0, "avg_risk_score": 0, "avg_security_score": 100, "by_status": {}}
    by_status = {}
    for d in deployments:
        by_status[d.status] = by_status.get(d.status, 0) + 1
    risk_scores = [d.risk_score for d in deployments if d.risk_score is not None]
    sec_scores = [d.security_score for d in deployments if d.security_score is not None]
    return {
        "total": len(deployments),
        "avg_risk_score": round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0,
        "avg_security_score": round(sum(sec_scores) / len(sec_scores), 1) if sec_scores else 100,
        "by_status": by_status,
    }
