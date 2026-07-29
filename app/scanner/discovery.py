"""Agentless host discovery using nmap.

We shell out to nmap with XML output and parse it with the stdlib. This gives
us: live hosts, MAC + vendor (when on the same L2 segment), reverse-DNS
hostname, NetBIOS/SMB hostname, open ports with service/product/version, and an
OS family guess.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("netview.discovery")

# Ports worth probing across a mixed Windows/Linux/printer/network estate.
DEFAULT_PORTS = (
    "21,22,23,25,53,80,110,135,139,143,161,389,443,445,515,631,993,995,"
    "1433,1521,3306,3389,5432,5900,5985,5986,8000,8080,8443,9100,27017"
)


@dataclass
class HostResult:
    ip: str
    mac: str | None = None
    vendor: str | None = None          # nmap's own OUI guess (we override with ours)
    hostname: str | None = None        # reverse DNS
    netbios_name: str | None = None    # from nbstat script
    reason: str = ""
    open_ports: list[dict[str, Any]] = field(default_factory=list)
    os_guess: str | None = None
    os_accuracy: int | None = None
    os_matches: list[dict[str, Any]] = field(default_factory=list)


def _build_argv(targets: list[str], ports: str, timing: int, os_detect: bool) -> list[str]:
    argv = [
        "nmap",
        "-oX", "-",            # XML to stdout
        "-Pn",                 # treat hosts as up; we scan ports directly
        "-T", str(timing),
        "-p", ports,
        "-sV",                 # service/version detection
        "--version-light",
        "-R",                  # reverse-DNS all
        "--script", "nbstat",  # NetBIOS name for Windows hosts
        "--max-retries", "2",
        "--host-timeout", "120s",
    ]
    if os_detect:
        argv.append("-O")
        argv.append("--osscan-limit")
    argv.extend(targets)
    return argv


def _parse_xml(xml_bytes: bytes) -> list[HostResult]:
    results: list[HostResult] = []
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        log.error("nmap XML parse error: %s", exc)
        return results

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") == "down":
            continue

        ip = None
        mac = None
        vendor = None
        for addr in host.findall("address"):
            atype = addr.get("addrtype")
            if atype in ("ipv4", "ipv6"):
                ip = addr.get("addr")
            elif atype == "mac":
                mac = (addr.get("addr") or "").upper() or None
                vendor = addr.get("vendor")
        if not ip:
            continue

        hr = HostResult(ip=ip, mac=mac, vendor=vendor)
        if status is not None:
            hr.reason = status.get("reason", "")

        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                hr.hostname = hn.get("name")

        ports_el = host.find("ports")
        if ports_el is not None:
            for p in ports_el.findall("port"):
                state = p.find("state")
                if state is None or state.get("state") != "open":
                    continue
                svc = p.find("service")
                entry = {
                    "port": int(p.get("portid")),
                    "proto": p.get("protocol"),
                    "service": svc.get("name") if svc is not None else None,
                    "product": svc.get("product") if svc is not None else None,
                    "version": svc.get("version") if svc is not None else None,
                    "extrainfo": svc.get("extrainfo") if svc is not None else None,
                }
                hr.open_ports.append(entry)

        # NetBIOS name from nbstat host script
        for hs in host.findall("hostscript/script"):
            if hs.get("id") == "nbstat":
                out = hs.get("output", "")
                # e.g. "NetBIOS name: PC-01, NetBIOS user: <unknown>, ..."
                for token in out.split(","):
                    token = token.strip()
                    if token.lower().startswith("netbios name:"):
                        name = token.split(":", 1)[1].strip()
                        if name and name != "<unknown>":
                            hr.netbios_name = name

        os_el = host.find("os")
        if os_el is not None:
            for m in os_el.findall("osmatch"):
                acc = int(m.get("accuracy", "0"))
                hr.os_matches.append({"name": m.get("name"), "accuracy": acc})
            if hr.os_matches:
                best = max(hr.os_matches, key=lambda x: x["accuracy"])
                hr.os_guess = best["name"]
                hr.os_accuracy = best["accuracy"]

        results.append(hr)
    return results


async def discover(
    subnets: list[str],
    ports: str = DEFAULT_PORTS,
    timing: int = 4,
    os_detect: bool = True,
) -> list[HostResult]:
    """Run nmap against the given CIDRs and return per-host results."""
    if not subnets:
        return []
    argv = _build_argv(subnets, ports, timing, os_detect)
    log.info("nmap: %s", " ".join(argv))
    proc = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode not in (0, 1):
        log.error("nmap exited %s: %s", proc.returncode, stderr.decode(errors="replace")[:500])
    results = _parse_xml(stdout)
    log.info("nmap found %d live host(s)", len(results))
    return results


def reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None
