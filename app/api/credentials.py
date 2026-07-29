"""Credential management endpoints. Secrets are encrypted at rest and never
returned to the client."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..crypto import encrypt
from ..database import get_session
from ..models import Credential
from ..schemas import CredentialIn, CredentialOut
from .deps import require_auth

router = APIRouter(prefix="/api/credentials", tags=["credentials"],
                   dependencies=[Depends(require_auth)])


def _out(c: Credential) -> dict:
    return {
        "id": c.id, "name": c.name, "kind": c.kind, "domain": c.domain,
        "username": c.username, "snmp_version": c.snmp_version, "enabled": c.enabled,
        "has_secret": bool(c.secret_enc or c.snmp_community_enc),
    }


@router.get("", response_model=list[CredentialOut])
def list_credentials(db: Session = Depends(get_session)):
    return [_out(c) for c in db.execute(select(Credential).order_by(Credential.kind, Credential.name)).scalars()]


@router.post("", response_model=CredentialOut)
def create_credential(payload: CredentialIn, db: Session = Depends(get_session)):
    if payload.kind not in ("windows", "ssh", "snmp"):
        raise HTTPException(400, "kind must be windows, ssh, or snmp")
    c = Credential(
        name=payload.name, kind=payload.kind, domain=payload.domain,
        username=payload.username, snmp_version=payload.snmp_version, enabled=payload.enabled,
    )
    if payload.kind == "snmp":
        c.snmp_community_enc = encrypt(payload.community or "")
    else:
        c.secret_enc = encrypt(payload.secret or "")
    db.add(c)
    db.commit()
    return _out(c)


@router.put("/{cred_id}", response_model=CredentialOut)
def update_credential(cred_id: int, payload: CredentialIn, db: Session = Depends(get_session)):
    c = db.get(Credential, cred_id)
    if not c:
        raise HTTPException(404, "Credential not found")
    c.name = payload.name
    c.domain = payload.domain
    c.username = payload.username
    c.snmp_version = payload.snmp_version
    c.enabled = payload.enabled
    # Only overwrite the secret if a new one was supplied.
    if payload.kind == "snmp":
        if payload.community:
            c.snmp_community_enc = encrypt(payload.community)
    elif payload.secret:
        c.secret_enc = encrypt(payload.secret)
    db.commit()
    return _out(c)


@router.delete("/{cred_id}")
def delete_credential(cred_id: int, db: Session = Depends(get_session)):
    c = db.get(Credential, cred_id)
    if not c:
        raise HTTPException(404, "Credential not found")
    db.delete(c)
    db.commit()
    return {"ok": True}
