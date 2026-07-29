"""SSH probe for Linux/Unix/macOS hosts.

Runs a few read-only commands to gather OS, kernel, hardware, and uptime.
Supports password or private-key auth. Blocking (paramiko) — run in a thread
pool executor.
"""
from __future__ import annotations

import io
import logging
from typing import Any

import paramiko

log = logging.getLogger("netview.ssh")

COMMANDS = {
    "hostname": "hostname -f 2>/dev/null || hostname",
    "os_release": "cat /etc/os-release 2>/dev/null | grep -E '^(PRETTY_NAME|NAME|VERSION)=' || sw_vers 2>/dev/null",
    "kernel": "uname -sr",
    "arch": "uname -m",
    "uptime": "uptime -p 2>/dev/null || uptime",
    "cpu": "grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//' || sysctl -n machdep.cpu.brand_string 2>/dev/null",
    "cpu_count": "nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null",
    "mem_kb": "grep -m1 MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || (sysctl -n hw.memsize 2>/dev/null | awk '{print $1/1024}')",
    "product": "cat /sys/class/dmi/id/product_name 2>/dev/null",
    "serial": "cat /sys/class/dmi/id/product_serial 2>/dev/null",
    "disk_root": "df -h / 2>/dev/null | tail -1 | awk '{print $2\" used \"$3\" (\"$5\")\"}'",
}


def _parse_os_release(text: str) -> str | None:
    pretty = None
    for line in text.splitlines():
        if line.startswith("PRETTY_NAME="):
            pretty = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("ProductName:") and pretty is None:
            pretty = line.split(":", 1)[1].strip()
    return pretty


def probe(
    host: str,
    username: str,
    password: str = "",
    private_key: str = "",
    port: int = 22,
    timeout: int = 15,
) -> dict[str, Any]:
    """Return SSH-collected data, or {} if we couldn't connect/auth."""
    result: dict[str, Any] = {"_ok": False}
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        kwargs: dict[str, Any] = {
            "hostname": host,
            "port": port,
            "username": username,
            "timeout": timeout,
            "banner_timeout": timeout,
            "auth_timeout": timeout,
            "look_for_keys": False,
            "allow_agent": False,
        }
        if private_key:
            pkey = None
            for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
                try:
                    pkey = cls.from_private_key(io.StringIO(private_key))
                    break
                except Exception:
                    continue
            if pkey is None:
                raise ValueError("unrecognized private key format")
            kwargs["pkey"] = pkey
        else:
            kwargs["password"] = password

        client.connect(**kwargs)

        out: dict[str, Any] = {}
        for label, cmd in COMMANDS.items():
            try:
                _in, stdout, _err = client.exec_command(cmd, timeout=timeout)
                out[label] = stdout.read().decode(errors="replace").strip()
            except Exception:
                out[label] = ""

        data: dict[str, Any] = {"raw": out}
        data["hostname"] = out.get("hostname") or None
        data["os_name"] = _parse_os_release(out.get("os_release", "")) or None
        data["kernel"] = out.get("kernel") or None
        data["arch"] = out.get("arch") or None
        data["uptime"] = out.get("uptime") or None
        data["cpu"] = out.get("cpu") or None
        data["cpu_count"] = out.get("cpu_count") or None
        mem = out.get("mem_kb", "")
        try:
            data["mem_bytes"] = int(float(mem)) * 1024 if mem else None
        except ValueError:
            data["mem_bytes"] = None
        data["product"] = out.get("product") or None
        data["serial"] = out.get("serial") or None
        data["disk_root"] = out.get("disk_root") or None
        data["_ok"] = True
        return data
    except Exception as exc:
        log.debug("SSH probe failed on %s: %s", host, exc)
        return result
    finally:
        try:
            client.close()
        except Exception:
            pass
