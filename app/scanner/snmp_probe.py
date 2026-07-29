"""SNMP probe for switches, routers, printers, UPSs, etc.

Pulls the standard system group plus interface counts and, for printers, page
counts and supply levels. SNMP v2c (community) is the common case; v3 auth is
supported via the credential's fields when provided.
"""
from __future__ import annotations

import logging
from typing import Any

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    get_cmd,
)

log = logging.getLogger("netview.snmp")

SYS_OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
}
IF_NUMBER = "1.3.6.1.2.1.2.1.0"
# Printer MIB
PRT_MARKER_LIFECOUNT = "1.3.6.1.2.1.43.10.2.1.4.1.1"  # page count


async def probe(host: str, community: str, timeout: int = 8) -> dict[str, Any]:
    """Return SNMP data or {} if the host doesn't answer."""
    result: dict[str, Any] = {"_ok": False}
    engine = SnmpEngine()
    try:
        target = await UdpTransportTarget.create((host, 161), timeout=timeout, retries=1)
        system: dict[str, Any] = {}
        for label, oid in SYS_OIDS.items():
            erri, errs, _, var_binds = await get_cmd(
                engine,
                CommunityData(community, mpModel=1),
                target,
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )
            if erri or errs:
                continue
            for _name, val in var_binds:
                pv = val.prettyPrint()
                if pv and "No Such" not in pv:
                    system[label] = pv

        if not system:
            return result  # no answer -> not SNMP-capable / wrong community

        result["system"] = system

        # interface count
        erri, errs, _, var_binds = await get_cmd(
            engine, CommunityData(community, mpModel=1), target, ContextData(),
            ObjectType(ObjectIdentity(IF_NUMBER)),
        )
        if not (erri or errs):
            for _n, v in var_binds:
                pv = v.prettyPrint()
                if pv.isdigit():
                    result["interface_count"] = int(pv)

        # printer page count (best effort)
        erri, errs, _, var_binds = await get_cmd(
            engine, CommunityData(community, mpModel=1), target, ContextData(),
            ObjectType(ObjectIdentity(PRT_MARKER_LIFECOUNT)),
        )
        if not (erri or errs):
            for _n, v in var_binds:
                pv = v.prettyPrint()
                if pv.isdigit():
                    result["page_count"] = int(pv)

        result["_ok"] = True
    except Exception as exc:
        log.debug("SNMP probe failed on %s: %s", host, exc)
    finally:
        try:
            engine.close_dispatcher()
        except Exception:
            pass
    return result
