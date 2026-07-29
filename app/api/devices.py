"""Device endpoints."""
from __future__ import annotations

import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..database import get_session
from ..models import Device
from ..schemas import DeviceDetail, DeviceSummary
from .deps import require_auth

router = APIRouter(prefix="/api/devices", tags=["devices"], dependencies=[Depends(require_auth)])


def _summary(d: Device) -> dict:
    mesh = d.mesh or {}
    return {
        "id": d.id, "ip": d.ip, "mac": d.mac, "hostname": d.hostname, "fqdn": d.fqdn,
        "device_type": d.device_type, "vendor": d.vendor, "os_name": d.os_name,
        "site": d.site, "online": d.online, "first_seen": d.first_seen,
        "last_seen": d.last_seen, "open_ports": d.open_ports or [],
        "mesh_agent": bool(mesh.get("agent_online")), "mesh_link": mesh.get("link"),
        "software_count": len(d.software or []),
    }


@router.get("", response_model=list[DeviceSummary])
def list_devices(
    db: Session = Depends(get_session),
    q: str | None = Query(None, description="search host/ip/mac/vendor"),
    type: str | None = None,
    site: str | None = None,
    online: bool | None = None,
):
    stmt = select(Device)
    if type:
        stmt = stmt.where(Device.device_type == type)
    if site:
        stmt = stmt.where(Device.site == site)
    if online is not None:
        stmt = stmt.where(Device.online == online)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(
            Device.ip.ilike(like), Device.mac.ilike(like), Device.hostname.ilike(like),
            Device.vendor.ilike(like), Device.os_name.ilike(like), Device.fqdn.ilike(like),
        ))
    stmt = stmt.order_by(Device.online.desc(), Device.ip)
    return [_summary(d) for d in db.execute(stmt).scalars()]


@router.get("/export.csv")
def export_csv(db: Session = Depends(get_session)):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ip", "mac", "hostname", "fqdn", "type", "vendor", "os", "site",
                "online", "mesh_agent", "open_ports", "software_count", "first_seen", "last_seen"])
    for d in db.execute(select(Device).order_by(Device.ip)).scalars():
        ports = " ".join(str(p.get("port")) for p in (d.open_ports or []))
        w.writerow([d.ip, d.mac or "", d.hostname or "", d.fqdn or "", d.device_type,
                    d.vendor or "", d.os_name or "", d.site or "", int(d.online),
                    int(bool((d.mesh or {}).get("agent_online"))), ports,
                    len(d.software or []), d.first_seen, d.last_seen])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=netview-inventory.csv"},
    )


@router.get("/{device_id}", response_model=DeviceDetail)
def get_device(device_id: int, db: Session = Depends(get_session)):
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(404, "Device not found")
    base = _summary(d)
    base.update({
        "nmap": d.nmap or {}, "wmi": d.wmi or {}, "snmp": d.snmp or {},
        "ssh": d.ssh or {}, "software": d.software or [], "mesh": d.mesh or {},
        "notes": d.notes,
    })
    return base


@router.patch("/{device_id}/notes")
def update_notes(device_id: int, payload: dict, db: Session = Depends(get_session)):
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(404, "Device not found")
    d.notes = payload.get("notes", "")
    db.commit()
    return {"ok": True}


@router.delete("/{device_id}")
def delete_device(device_id: int, db: Session = Depends(get_session)):
    d = db.get(Device, device_id)
    if not d:
        raise HTTPException(404, "Device not found")
    db.delete(d)
    db.commit()
    return {"ok": True}
