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


@router.post("/recorrelate")
async def recorrelate(db: Session = Depends(get_session)):
    """Re-run MeshCentral correlation over existing devices, without scanning.

    Correlation only needs a clean connection to MeshCentral, so decoupling it
    from the scan means you can refresh agent matches any time the server has
    outbound access — even if the scan-time correlation failed (e.g. the link
    was cut mid-scan)."""
    from ..meshcentral import MeshCentralClient, correlate
    from ..models import Device
    from ..runtime import get_mesh

    cfg = get_mesh(db)
    if not cfg.get("url"):
        return {"ok": False, "error": "MeshCentral is not configured"}

    devices = list(db.execute(select(Device)).scalars())
    if not devices:
        return {"ok": False, "error": "No devices yet — run a scan first"}

    client = MeshCentralClient(cfg["url"], cfg["username"], cfg["password"],
                               cfg["token"], cfg["verify_tls"])
    try:
        nodes = await client.get_nodes()
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}

    mapping = correlate(devices, nodes, client.device_link)
    for dev in devices:
        dev.mesh = mapping.get(dev.id, {})
    db.commit()
    return {"ok": True, "nodes": len(nodes), "correlated": len(mapping)}
