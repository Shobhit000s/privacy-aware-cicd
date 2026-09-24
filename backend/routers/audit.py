"""backend/routers/audit.py — read + integrity-verify the audit trail."""
import hashlib
import json
from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

import models
import schemas
from database import get_db

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("", response_model=List[schemas.AuditEventOut])
def list_audit_events(limit: int = 100, db: Session = Depends(get_db)):
    return (
        db.query(models.AuditEvent)
        .order_by(models.AuditEvent.id.desc())
        .limit(limit)
        .all()
    )


@router.get("/verify")
def verify_audit_chain(db: Session = Depends(get_db)):
    """Recomputes each event's hash from its stored fields and confirms the
    chain hasn't been tampered with — the same property audit_logger.py
    provides for the file-based log, exposed here as an API for the DB-backed
    trail."""
    events = db.query(models.AuditEvent).order_by(models.AuditEvent.id.asc()).all()
    prev = "0" * 64
    for e in events:
        body = {
            "deployment_id": e.deployment_id,
            "event_type": e.event_type,
            "actor": e.actor,
            "detail": e.detail,
            "prev_hash": e.prev_hash,
            "timestamp": e.timestamp.isoformat() if hasattr(e.timestamp, "isoformat") else str(e.timestamp),
        }
        recomputed = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        if recomputed != e.event_hash or e.prev_hash != prev:
            return {"integrity_ok": False, "broken_at_event_id": e.id}
        prev = e.event_hash
    return {"integrity_ok": True, "events_checked": len(events)}
