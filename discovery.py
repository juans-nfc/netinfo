"""
discovery.py - find live hosts and take a first guess at what they are.

Layers, cheapest first:
  1. Async TCP connect scan against a curated port list. Fast, no root needed,
     works across a routed site-to-site VPN (unlike ARP/broadcast methods).
  2. Local ARP table read for MAC + vendor hint (only works for hosts on the
     collector's own L2 segment).
  3. Optional nmap hand-off if the binary is present, for better OS/service fp.

The open ports become a routing hint: 22 -> try SSH, 5985/135/445 -> try WinRM,
9100 -> printer, etc. SNMP (UDP/161) can't be TCP-probed, so we just attempt
SNMP against everything alive when a community/creds are configured.
"""
import asyncio
import ipaddress
import re
import shutil
import subprocess

# port -> (proto, human hint, routing tag)
PROBE_PORTS = {
    22:   ("tcp", "ssh",        "linux"),
    23:   ("tcp", "telnet",     "network"),
    80:   ("tcp", "http",       "web"),
    443:  ("tcp", "https",      "web"),
    135:  ("tcp", "msrpc",      "windows"),
    139:  ("tcp", "netbios",    "windows"),
    445:  ("tcp", "smb",        "windows"),
    3389: ("tcp", "rdp",        "windows"),
    5985: ("tcp", "winrm-http", "windows"),
    5986: ("tcp", "winrm-https","windows"),
    515:  ("tcp", "lpd",        "printer"),
    9100: ("tcp", "jetdirect",  "printer"),
    631:  ("tcp", "ipp",        "printer"),
}


async def _probe(ip, port, timeout):
    try:
        fut = asyncio.open_connection(str(ip), port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return port
    except Exception:
        return None


async def _scan_host(ip, timeout):
    tasks = [_probe(ip, p, timeout) for p in PROBE_PORTS]
    results = await asyncio.gather(*tasks)
    return str(ip), [p for p in results if p]


async def _scan_cidr(cidr, timeout, concurrency):
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = list(net.hosts()) if net.num_addresses > 2 else [net.network_address]
    sem = asyncio.Semaphore(concurrency)

    async def guarded(ip):
        async with sem:
            return await _scan_host(ip, timeout)

    return await asyncio.gather(*[guarded(ip) for ip in hosts])


def _read_arp():
    """Return {ip: mac} from the local ARP/neighbour table. On-subnet only."""
    table = {}
    cmd = None
    if shutil.which("ip"):
        cmd = ["ip", "neigh"]
    elif shutil.which("arp"):
        cmd = ["arp", "-an"]
    if not cmd:
        return table
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return table
    for line in out.splitlines():
        ipm = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        macm = re.search(r"([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5})", line)
        if ipm and macm:
            table[ipm.group(1)] = macm.group(1).lower()
    return table


def route_tags(open_ports):
    """Turn a list of open ports into device-type hints for the orchestrator."""
    tags = set()
    for p in open_ports:
        if p in PROBE_PORTS:
            tags.add(PROBE_PORTS[p][2])
    return tags


def discover(cidrs, timeout=0.6, concurrency=256):
    """
    Scan the given CIDRs. Returns list of dicts:
      {ip, mac, open_ports:[int], tags:set(str)}
    Only hosts with at least one open probed port are returned. If your fleet
    firewalls all these ports you'll want to add an ICMP/nmap pass (see README).
    """
    loop = asyncio.new_event_loop()
    try:
        all_results = []
        for cidr in cidrs:
            all_results.extend(loop.run_until_complete(
                _scan_cidr(cidr, timeout, concurrency)))
    finally:
        loop.close()

    arp = _read_arp()
    live = []
    for ip, ports in all_results:
        if not ports:
            continue
        live.append({
            "ip": ip,
            "mac": arp.get(ip),
            "open_ports": ports,
            "tags": route_tags(ports),
        })
    return live


def nmap_available():
    return shutil.which("nmap") is not None
