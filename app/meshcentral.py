"""MeshCentral integration via the WebSocket control API (/control.ashx).

Authenticates with the `x-meshauth` header (base64 user/pass, plus an optional
2FA token) or a login token, lists managed devices, and exposes them for
correlation against scan results. No agent or REST endpoint required — this is
the same channel the MeshCentral web UI uses.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import ssl
from dataclasses import dataclass, field
from typing import Any

import websockets

log = logging.getLogger("netview.mesh")


@dataclass
class MeshNode:
    nodeid: str
    name: str
    meshid: str = ""
    meshname: str = ""
    host: str | None = None
    icon: int | None = None
    conn: int = 0                 # connectivity bitmask; bit 1 = agent connected
    pwr: int | None = None
    os_desc: str | None = None
    agent_ver: str | None = None
    tags: list[str] = field(default_factory=list)
    last_addr: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def agent_online(self) -> bool:
        return bool(self.conn & 1)


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _control_url(base: str) -> str:
    base = base.rstrip("/")
    if base.startswith("http://"):
        base = "ws://" + base[len("http://"):]
    elif base.startswith("https://"):
        base = "wss://" + base[len("https://"):]
    elif not base.startswith(("ws://", "wss://")):
        base = "wss://" + base
    return base + "/control.ashx"


def https_base(base: str) -> str:
    base = base.rstrip("/")
    for pfx in ("ws://", "wss://", "http://", "https://"):
        if base.startswith(pfx):
            base = base[len(pfx):]
            break
    return "https://" + base


class MeshCentralClient:
    def __init__(
        self,
        url: str,
        username: str = "",
        password: str = "",
        token: str = "",
        verify_tls: bool = True,
    ):
        self.url = _control_url(url)
        self.https_base = https_base(url)
        self.username = username
        self.password = password
        self.token = token
        self.verify_tls = verify_tls

    def _headers(self) -> dict[str, str]:
        # MeshCentral accepts: x-meshauth: b64(user),b64(pass)[,b64(2fa)]
        parts = [_b64(self.username), _b64(self.password)]
        if self.token:
            parts.append(_b64(self.token))
        return {"x-meshauth": ",".join(parts)}

    def _ssl(self):
        if self.url.startswith("wss://"):
            ctx = ssl.create_default_context()
            if not self.verify_tls:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            return ctx
        return None

    async def _connect(self):
        headers = self._headers()
        ssl_ctx = self._ssl()
        # websockets renamed extra_headers -> additional_headers across versions.
        try:
            return await websockets.connect(
                self.url, additional_headers=headers, ssl=ssl_ctx,
                max_size=64 * 1024 * 1024, open_timeout=20,
            )
        except TypeError:
            return await websockets.connect(
                self.url, extra_headers=headers, ssl=ssl_ctx,
                max_size=64 * 1024 * 1024, open_timeout=20,
            )

    async def _request(self, action_out: str, action_in: str, payload: dict | None = None,
                       timeout: int = 25) -> dict:
        """Send one action and wait for the first reply whose action matches."""
        async with await self._connect() as ws:
            msg = {"action": action_out}
            if payload:
                msg.update(payload)
            await ws.send(json.dumps(msg))
            deadline = asyncio.get_event_loop().time() + timeout
            while True:
                remaining = deadline - asyncio.get_event_loop().time()
                if remaining <= 0:
                    raise TimeoutError(f"no '{action_in}' reply within {timeout}s")
                raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if data.get("action") == action_in:
                    return data

    async def test(self) -> dict:
        """Verify connectivity/credentials via serverinfo."""
        return await self._request("serverinfo", "serverinfo")

    async def get_nodes(self) -> list[MeshNode]:
        data = await self._request("nodes", "nodes")
        nodes_by_mesh: dict[str, list[dict]] = data.get("nodes", {}) or {}
        # device group names
        try:
            meshes = await self._request("meshes", "meshes")
            mesh_names = {m.get("_id"): m.get("name", "") for m in meshes.get("meshes", [])}
        except Exception:
            mesh_names = {}

        out: list[MeshNode] = []
        for meshid, nodes in nodes_by_mesh.items():
            for n in nodes:
                out.append(MeshNode(
                    nodeid=n.get("_id", ""),
                    name=n.get("name", ""),
                    meshid=meshid,
                    meshname=mesh_names.get(meshid, ""),
                    host=n.get("host") or n.get("ip"),
                    icon=n.get("icon"),
                    conn=n.get("conn", 0) or 0,
                    pwr=n.get("pwr"),
                    os_desc=n.get("osdesc") or n.get("agent", {}).get("osdesc"),
                    agent_ver=(n.get("agent") or {}).get("ver"),
                    tags=n.get("tags", []) or [],
                    last_addr=n.get("lastaddr"),
                    raw=n,
                ))
        log.info("MeshCentral returned %d node(s)", len(out))
        return out

    def device_link(self, nodeid: str) -> str:
        return f"{self.https_base}/#p=devices&node={nodeid}"


def correlate(devices, mesh_nodes: list[MeshNode], link_fn) -> dict[int, dict]:
    """Match Device rows to MeshNodes by hostname then IP.

    Returns {device_id: mesh_summary}. `devices` is an iterable of ORM Device
    objects (needs id, ip, hostname, fqdn, and wmi/ssh hostnames).
    """
    by_name: dict[str, MeshNode] = {}
    by_host: dict[str, MeshNode] = {}
    for mn in mesh_nodes:
        if mn.name:
            by_name.setdefault(mn.name.strip().lower(), mn)
        if mn.host:
            by_host.setdefault(mn.host.strip().lower(), mn)

    result: dict[int, dict] = {}
    for dev in devices:
        candidates = []
        wmi_name = (dev.wmi or {}).get("computer", {}).get("name") if dev.wmi else None
        ssh_name = (dev.ssh or {}).get("hostname") if dev.ssh else None
        for cand in (dev.hostname, dev.fqdn, wmi_name, ssh_name):
            if cand:
                short = cand.split(".")[0].strip().lower()
                candidates.extend([cand.strip().lower(), short])
        match = None
        for c in candidates:
            if c in by_name:
                match = by_name[c]
                break
        if match is None and dev.ip:
            match = by_host.get(dev.ip.strip().lower())
        if match is not None:
            result[dev.id] = {
                "nodeid": match.nodeid,
                "name": match.name,
                "mesh": match.meshname,
                "agent_online": match.agent_online,
                "os_desc": match.os_desc,
                "agent_ver": match.agent_ver,
                "tags": match.tags,
                "link": link_fn(match.nodeid),
            }
    return result
