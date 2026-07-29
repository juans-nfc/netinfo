"""Full-scan orchestration.

Pipeline: nmap discovery -> classify -> per-host deep probes (WMI / SSH / SNMP,
run with bounded concurrency) -> MeshCentral correlation -> upsert into the DB.
Blocking probes (impacket, paramiko) run in a thread pool; SNMP and MeshCentral
are natively async.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from sqlalchemy import select

from ..config import get_settings
from ..crypto import decrypt
from ..models import Credential, Device, ScanRun
from ..runtime import get_mesh, get_subnets
from . import discovery, snmp_probe, ssh_probe, wmi_probe
from .oui import vendor_for

log = logging.getLogger("netview.scan")


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _classify_ports(ports: set[int]) -> dict[str, bool]:
    return {
        "windows": bool(ports & {135, 445, 3389, 5985, 5986}),
        "ssh": 22 in ports,
        "snmp": 161 in ports,
        "printer": bool(ports & {515, 631, 9100}),
        "web": bool(ports & {80, 443, 8080, 8443}),
    }


def _site_for_ip(ip: str, subnet_labels: list[dict]) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for s in subnet_labels:
        try:
            if addr in ipaddress.ip_network(s["cidr"], strict=False):
                return s.get("label") or s["cidr"]
        except ValueError:
            continue
    return None


def _load_creds(db):
    wins, sshs, snmps = [], [], []
    for c in db.execute(select(Credential).where(Credential.enabled == True)).scalars():  # noqa: E712
        if c.kind == "windows":
            wins.append({"domain": c.domain or "", "username": c.username or "",
                         "password": decrypt(c.secret_enc or "")})
        elif c.kind == "ssh":
            # secret is a password or a PEM private key; the probe decides which.
            sshs.append({"username": c.username or "", "secret": decrypt(c.secret_enc or "")})
        elif c.kind == "snmp":
            snmps.append({"community": decrypt(c.snmp_community_enc or "")})
    return wins, sshs, snmps


def _os_family(text: str | None) -> str | None:
    if not text:
        return None
    t = text.lower()
    if "windows" in t:
        return "windows"
    if "darwin" in t or "mac os" in t or "macos" in t:
        return "mac"
    if any(k in t for k in ("linux", "ubuntu", "debian", "centos", "red hat", "rhel", "fedora")):
        return "linux"
    return None


async def _probe_host(
    hr: discovery.HostResult,
    caps: dict[str, bool],
    wins: list[dict],
    sshs: list[dict],
    snmps: list[dict],
    pool: ThreadPoolExecutor,
    sem: asyncio.Semaphore,
    settings,
) -> dict[str, Any]:
    """Run applicable deep probes for one host. Returns merged probe data."""
    loop = asyncio.get_event_loop()
    out: dict[str, Any] = {"wmi": {}, "ssh": {}, "snmp": {}}

    async with sem:
        # --- Windows / WMI ---
        if caps["windows"] and wins:
            for cred in wins:
                try:
                    data = await asyncio.wait_for(
                        loop.run_in_executor(
                            pool, wmi_probe.probe, hr.ip, cred["domain"], cred["username"],
                            cred["password"], settings.wmi_software_inventory, settings.probe_timeout,
                        ),
                        timeout=settings.probe_timeout + 15,
                    )
                except (asyncio.TimeoutError, Exception) as exc:  # noqa: BLE001
                    log.debug("WMI executor error on %s: %s", hr.ip, exc)
                    data = {}
                if data.get("_ok"):
                    out["wmi"] = data
                    break

        # --- SSH (Linux/Unix) ---
        if caps["ssh"] and sshs and not out["wmi"].get("_ok"):
            for cred in sshs:
                secret = cred.get("secret", "")
                is_key = secret.strip().startswith("-----BEGIN")
                try:
                    data = await asyncio.wait_for(
                        loop.run_in_executor(
                            pool, ssh_probe.probe, hr.ip, cred["username"],
                            "" if is_key else secret,
                            secret if is_key else "",
                            22, settings.probe_timeout,
                        ),
                        timeout=settings.probe_timeout + 10,
                    )
                except (asyncio.TimeoutError, Exception) as exc:  # noqa: BLE001
                    log.debug("SSH executor error on %s: %s", hr.ip, exc)
                    data = {}
                if data.get("_ok"):
                    out["ssh"] = data
                    break

        # --- SNMP (network gear / printers) ---
        if (caps["snmp"] or caps["printer"]) and snmps:
            for cred in snmps:
                try:
                    data = await snmp_probe.probe(hr.ip, cred["community"], timeout=8)
                except Exception as exc:  # noqa: BLE001
                    log.debug("SNMP error on %s: %s", hr.ip, exc)
                    data = {}
                if data.get("_ok"):
                    out["snmp"] = data
                    break

    return out


def _merge_device_fields(hr: discovery.HostResult, probes: dict, subnet_labels: list[dict]) -> dict:
    wmi = probes.get("wmi") or {}
    ssh = probes.get("ssh") or {}
    snmp = probes.get("snmp") or {}
    caps = _classify_ports({p["port"] for p in hr.open_ports})

    # hostname
    hostname = (
        (wmi.get("computer", {}) or {}).get("name")
        or hr.netbios_name
        or ssh.get("hostname")
        or hr.hostname
    )
    if hostname:
        hostname = hostname.split(".")[0]
    fqdn = hr.hostname if hr.hostname and "." in hr.hostname else None

    # os
    os_name = (
        (wmi.get("os", {}) or {}).get("caption")
        or ssh.get("os_name")
        or (snmp.get("system", {}) or {}).get("sysDescr")
        or hr.os_guess
    )

    # device type
    if wmi.get("_ok"):
        device_type = "windows"
    elif ssh.get("_ok"):
        device_type = _os_family(ssh.get("os_name")) or "linux"
    elif snmp.get("_ok"):
        if snmp.get("page_count") is not None or "printer" in (str(snmp.get("system", {}).get("sysDescr", "")).lower()):
            device_type = "printer"
        else:
            device_type = "network"
    elif caps["printer"]:
        device_type = "printer"
    else:
        device_type = _os_family(hr.os_guess) or "unknown"

    vendor = vendor_for(hr.mac)

    return {
        "hostname": hostname,
        "fqdn": fqdn,
        "os_name": os_name,
        "device_type": device_type,
        "vendor": vendor,
        "site": _site_for_ip(hr.ip, subnet_labels),
        "open_ports": hr.open_ports,
        "nmap": {
            "os_guess": hr.os_guess,
            "os_accuracy": hr.os_accuracy,
            "os_matches": hr.os_matches[:5],
            "reason": hr.reason,
        },
        "wmi": wmi,
        "ssh": ssh,
        "snmp": snmp,
        "software": wmi.get("software", []) if wmi.get("_ok") else [],
    }


def _upsert(db, hr: discovery.HostResult, fields: dict, now: dt.datetime) -> Device:
    dev = None
    if hr.mac:
        dev = db.execute(select(Device).where(Device.mac == hr.mac)).scalar_one_or_none()
        if dev is None:
            # adopt an existing IP-only row
            dev = db.execute(
                select(Device).where(Device.ip == hr.ip, Device.mac.is_(None))
            ).scalar_one_or_none()
            if dev is not None:
                dev.mac = hr.mac
    if dev is None:
        dev = db.execute(select(Device).where(Device.ip == hr.ip)).scalar_one_or_none()

    if dev is None:
        dev = Device(ip=hr.ip, mac=hr.mac, first_seen=now)
        db.add(dev)

    dev.ip = hr.ip
    if hr.mac:
        dev.mac = hr.mac
    for k, v in fields.items():
        setattr(dev, k, v)
    dev.online = True
    dev.last_seen = now
    return dev


async def run_scan(
    session_factory: Callable,
    trigger: str = "manual",
    progress_cb: Callable[[dict], None] | None = None,
) -> int:
    """Execute a full scan. Returns the ScanRun id."""
    settings = get_settings()
    db = session_factory()
    subnet_labels = get_subnets(db)
    subnets = [s["cidr"] for s in subnet_labels]

    run = ScanRun(trigger=trigger, subnets=subnets, status="running", started_at=_utcnow())
    db.add(run)
    db.commit()
    run_id = run.id

    def report(**kw):
        if progress_cb:
            progress_cb(kw)

    logbuf: list[str] = []

    def note(msg: str):
        log.info(msg)
        logbuf.append(f"{_utcnow().isoformat()}  {msg}")

    try:
        if not subnets:
            raise RuntimeError("No subnets configured. Set them in Settings or NETVIEW_SUBNETS.")

        note(f"Discovery starting on {', '.join(subnets)}")
        report(phase="discovery", message="Running nmap discovery")
        hosts = await discovery.discover(
            subnets, timing=settings.nmap_timing, os_detect=settings.nmap_os_detect
        )
        note(f"Discovery found {len(hosts)} live host(s)")
        run.hosts_found = len(hosts)
        db.commit()

        wins, sshs, snmps = _load_creds(db)
        note(f"Credentials: {len(wins)} windows, {len(sshs)} ssh, {len(snmps)} snmp")

        sem = asyncio.Semaphore(settings.max_concurrency)
        now = _utcnow()
        probed = 0
        with ThreadPoolExecutor(max_workers=settings.max_concurrency) as pool:
            async def worker(hr: discovery.HostResult):
                nonlocal probed
                caps = _classify_ports({p["port"] for p in hr.open_ports})
                probes = await _probe_host(hr, caps, wins, sshs, snmps, pool, sem, settings)
                fields = _merge_device_fields(hr, probes, subnet_labels)
                _upsert(db, hr, fields, now)
                db.commit()
                probed += 1
                report(phase="probe", done=probed, total=len(hosts),
                        message=f"Probed {hr.ip} ({fields['device_type']})")

            await asyncio.gather(*(worker(h) for h in hosts))

        run.hosts_probed = probed
        db.commit()
        note(f"Deep probes complete: {probed} host(s)")

        # Mark hosts in scanned subnets that we didn't see as offline
        seen_ips = {h.ip for h in hosts}
        for dev in db.execute(select(Device)).scalars():
            if dev.site is not None and _site_for_ip(dev.ip, subnet_labels) is not None:
                if dev.ip not in seen_ips and dev.online:
                    dev.online = False
        db.commit()

        # MeshCentral correlation
        mesh_cfg = get_mesh(db)
        if mesh_cfg.get("url"):
            try:
                report(phase="mesh", message="Correlating with MeshCentral")
                from ..meshcentral import MeshCentralClient, correlate
                client = MeshCentralClient(
                    mesh_cfg["url"], mesh_cfg["username"], mesh_cfg["password"],
                    mesh_cfg["token"], mesh_cfg["verify_tls"],
                )
                nodes = await client.get_nodes()
                devices = list(db.execute(select(Device)).scalars())
                mapping = correlate(devices, nodes, client.device_link)
                for dev in devices:
                    dev.mesh = mapping.get(dev.id, {})
                db.commit()
                note(f"MeshCentral: {len(nodes)} nodes, {len(mapping)} correlated")
            except Exception as exc:  # noqa: BLE001
                note(f"MeshCentral correlation failed: {exc}")

        run.status = "done"
        run.finished_at = _utcnow()
        run.log = "\n".join(logbuf)
        db.commit()
        report(phase="done", message="Scan complete")
    except Exception as exc:  # noqa: BLE001
        log.exception("Scan failed")
        run.status = "error"
        run.error = str(exc)
        run.finished_at = _utcnow()
        run.log = "\n".join(logbuf)
        db.commit()
        report(phase="error", message=str(exc))
    finally:
        db.close()
    return run_id
