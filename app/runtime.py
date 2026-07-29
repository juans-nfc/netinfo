"""Effective runtime configuration.

Subnets and MeshCentral connection can be set either via environment (.env) or
from the UI (persisted in the settings table). The DB value, when present,
takes precedence so operators can change targets without redeploying.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from .config import get_settings
from .crypto import decrypt, encrypt
from .models import Setting


def get_subnets(db: Session) -> list[dict]:
    row = db.get(Setting, "subnets")
    if row and row.value:
        return [s for s in row.value if s.get("cidr")]
    return [{"cidr": c, "label": c} for c in get_settings().subnet_list]


def set_subnets(db: Session, subnets: list[dict]) -> None:
    cleaned = [{"cidr": s["cidr"].strip(), "label": (s.get("label") or s["cidr"]).strip()}
               for s in subnets if s.get("cidr")]
    row = db.get(Setting, "subnets")
    if row is None:
        row = Setting(key="subnets", value=cleaned)
        db.add(row)
    else:
        row.value = cleaned
    db.commit()


def get_mesh(db: Session) -> dict:
    """Effective mesh config (with decrypted secrets) for internal use."""
    settings = get_settings()
    row = db.get(Setting, "mesh")
    if row and row.value and row.value.get("url"):
        v = row.value
        return {
            "url": v.get("url", ""),
            "username": v.get("username", ""),
            "password": decrypt(v.get("password_enc", "")),
            "token": decrypt(v.get("token_enc", "")),
            "verify_tls": v.get("verify_tls", True),
        }
    return {
        "url": settings.mesh_url, "username": settings.mesh_user,
        "password": settings.mesh_password, "token": settings.mesh_token,
        "verify_tls": settings.mesh_verify_tls,
    }


def set_mesh(db: Session, *, url: str, username: str, password: str | None,
             token: str | None, verify_tls: bool) -> None:
    row = db.get(Setting, "mesh")
    existing = (row.value if row else {}) or {}
    value = {
        "url": url.strip(),
        "username": username.strip(),
        "verify_tls": verify_tls,
        # keep existing secret if a new one isn't provided
        "password_enc": encrypt(password) if password else existing.get("password_enc", ""),
        "token_enc": encrypt(token) if token else existing.get("token_enc", ""),
    }
    if row is None:
        row = Setting(key="mesh", value=value)
        db.add(row)
    else:
        row.value = value
    db.commit()
