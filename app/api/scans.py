"""Scan control endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_session
from ..models import ScanRun
from ..scan_manager import manager
from ..schemas import ScanRunOut
from .deps import require_auth

router = APIRouter(prefix="/api/scan", tags=["scan"], dependencies=[Depends(require_auth)])


@router.post("/run")
def start_scan():
    started = manager.start(trigger="manual")
    return {"started": started, "already_running": not started}


@router.get("/status")
def scan_status():
    return {"running": manager.running, "progress": manager.progress}


@router.get("/history", response_model=list[ScanRunOut])
def scan_history(db: Session = Depends(get_session), limit: int = 25):
    rows = db.execute(select(ScanRun).order_by(ScanRun.started_at.desc()).limit(limit)).scalars()
    return list(rows)
