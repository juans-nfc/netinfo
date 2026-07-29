"""Settings endpoints: subnets, MeshCentral connection, scan parameters."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..config import get_settings
from ..database import get_session
from ..meshcentral import MeshCentralClient
from ..runtime import get_mesh, get_subnets, set_mesh, set_subnets
from ..schemas import MeshConfigIn, SubnetIn
from .deps import require_auth

router = APIRouter(prefix="/api/settings", tags=["settings"], dependencies=[Depends(require_auth)])


@router.get("/subnets")
def read_subnets(db: Session = Depends(get_session)):
    return get_subnets(db)


@router.put("/subnets")
def write_subnets(subnets: list[SubnetIn], db: Session = Depends(get_session)):
    set_subnets(db, [s.model_dump() for s in subnets])
    return {"ok": True, "subnets": get_subnets(db)}


@router.get("/mesh")
def read_mesh(db: Session = Depends(get_session)):
    cfg = get_mesh(db)
    return {
        "url": cfg["url"], "username": cfg["username"],
        "verify_tls": cfg["verify_tls"],
        "has_password": bool(cfg["password"]), "has_token": bool(cfg["token"]),
    }


@router.put("/mesh")
def write_mesh(payload: MeshConfigIn, db: Session = Depends(get_session)):
    set_mesh(db, url=payload.url, username=payload.username, password=payload.password,
             token=payload.token, verify_tls=payload.verify_tls)
    return {"ok": True}


@router.post("/mesh/test")
async def test_mesh(db: Session = Depends(get_session)):
    cfg = get_mesh(db)
    if not cfg["url"]:
        return {"ok": False, "error": "No MeshCentral URL configured"}
    client = MeshCentralClient(cfg["url"], cfg["username"], cfg["password"],
                               cfg["token"], cfg["verify_tls"])
    try:
        info = await client.test()
        nodes = await client.get_nodes()
        return {"ok": True, "server": info.get("name"),
                "node_count": len(nodes),
                "agents_online": sum(1 for n in nodes if n.agent_online)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}


@router.get("/scan")
def read_scan_params():
    s = get_settings()
    return {
        "nmap_timing": s.nmap_timing, "nmap_os_detect": s.nmap_os_detect,
        "max_concurrency": s.max_concurrency, "probe_timeout": s.probe_timeout,
        "wmi_software_inventory": s.wmi_software_inventory, "scan_cron": s.scan_cron,
    }
