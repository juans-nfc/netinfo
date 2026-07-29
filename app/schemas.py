"""API request/response schemas."""
from __future__ import annotations

import datetime as dt
from typing import Any

from pydantic import BaseModel


class DeviceSummary(BaseModel):
    id: int
    ip: str
    mac: str | None
    hostname: str | None
    fqdn: str | None
    device_type: str
    vendor: str | None
    os_name: str | None
    site: str | None
    online: bool
    first_seen: dt.datetime
    last_seen: dt.datetime
    open_ports: list[Any]
    mesh_agent: bool
    mesh_link: str | None
    software_count: int


class DeviceDetail(DeviceSummary):
    nmap: dict[str, Any]
    wmi: dict[str, Any]
    snmp: dict[str, Any]
    ssh: dict[str, Any]
    software: list[Any]
    mesh: dict[str, Any]
    notes: str | None


class CredentialIn(BaseModel):
    name: str
    kind: str  # windows/ssh/snmp
    domain: str | None = None
    username: str | None = None
    secret: str | None = None       # password or PEM key (windows/ssh)
    snmp_version: str | None = "v2c"
    community: str | None = None    # snmp
    enabled: bool = True


class CredentialOut(BaseModel):
    id: int
    name: str
    kind: str
    domain: str | None
    username: str | None
    snmp_version: str | None
    enabled: bool
    has_secret: bool


class SubnetIn(BaseModel):
    cidr: str
    label: str | None = None


class MeshConfigIn(BaseModel):
    url: str = ""
    username: str = ""
    password: str = ""
    token: str = ""
    verify_tls: bool = True


class ScanRunOut(BaseModel):
    id: int
    started_at: dt.datetime
    finished_at: dt.datetime | None
    status: str
    trigger: str
    subnets: list[Any]
    hosts_found: int
    hosts_probed: int
    error: str | None
