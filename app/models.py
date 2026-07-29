"""ORM models."""
from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy import JSON, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Device(Base):
    """A discovered network asset. Keyed on MAC when known, else IP."""

    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("mac", name="uq_device_mac"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # Identity / correlation keys
    mac: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    fqdn: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Classification
    device_type: Mapped[str] = mapped_column(String(32), default="unknown")  # windows/linux/printer/network/mac/other/unknown
    vendor: Mapped[str | None] = mapped_column(String(128), nullable=True)   # MAC OUI vendor
    os_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    site: Mapped[str | None] = mapped_column(String(64), nullable=True)      # derived from subnet label

    # Status
    online: Mapped[bool] = mapped_column(default=True)
    first_seen: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    # Rich data captured per probe, stored as JSON blobs.
    open_ports: Mapped[list[Any]] = mapped_column(JSON, default=list)   # [{port, proto, service, product, version}]
    nmap: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)    # {os_guess, os_accuracy, ...}
    wmi: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)     # full windows detail
    snmp: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    ssh: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    software: Mapped[list[Any]] = mapped_column(JSON, default=list)     # [{name, version, publisher}]
    mesh: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)    # correlated MeshCentral node

    # Operator fields
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="running")  # running/done/error
    trigger: Mapped[str] = mapped_column(String(16), default="manual")  # manual/scheduled
    subnets: Mapped[list[Any]] = mapped_column(JSON, default=list)
    hosts_found: Mapped[int] = mapped_column(Integer, default=0)
    hosts_probed: Mapped[int] = mapped_column(Integer, default=0)
    log: Mapped[str] = mapped_column(Text, default="")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class Credential(Base):
    """Reusable scan credential. Passwords/keys stored encrypted."""

    __tablename__ = "credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    kind: Mapped[str] = mapped_column(String(16))  # windows/ssh/snmp
    # windows/ssh
    domain: Mapped[str | None] = mapped_column(String(128), nullable=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    secret_enc: Mapped[str | None] = mapped_column(Text, nullable=True)      # encrypted password or ssh key
    # snmp
    snmp_version: Mapped[str | None] = mapped_column(String(8), nullable=True)  # v2c/v3
    snmp_community_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
