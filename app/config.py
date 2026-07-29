"""Application configuration, loaded from environment / .env."""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NETVIEW_", env_file=".env", extra="ignore")

    # --- Web / serving ---
    # Set this to the sub-path the app is served under behind a reverse proxy
    # (e.g. "/netview"). Only used so API docs generate correct links; the
    # frontend uses relative URLs so it works under any prefix.
    root_path: str = ""
    host: str = "0.0.0.0"
    port: int = 8850

    # Optional HTTP basic auth for the UI/API. Leave user blank to disable.
    ui_user: str = ""
    ui_password: str = ""

    # --- Storage ---
    data_dir: str = "/app/data"

    # Secret used to encrypt stored scan credentials at rest. MUST be set to a
    # stable random value in production; if unset a per-boot key is generated
    # and stored credentials become unreadable after a restart.
    secret_key: str = ""

    # --- Scanning defaults ---
    # Comma-separated CIDRs to scan, e.g. "10.0.1.0/24,10.0.2.0/24,10.0.3.0/24".
    # Can also be managed from the UI (Settings). This is the initial seed.
    subnets: str = ""
    # Max concurrent deep probes (WMI/SSH/SNMP) during a scan.
    max_concurrency: int = 24
    # Per-host deep-probe timeout, seconds.
    probe_timeout: int = 30
    # nmap timing template 0-5 (higher = faster/louder).
    nmap_timing: int = 4
    # Run nmap OS detection (-O). Requires raw sockets (privileged/host net).
    nmap_os_detect: bool = True
    # Windows software inventory method: "registry" | "win32product" | "off".
    wmi_software_inventory: str = "registry"

    # --- Scheduler ---
    # Cron-style schedule for automatic scans. Empty disables the schedule.
    # Example: "0 6 * * *" (daily 06:00). Uses the container's timezone.
    scan_cron: str = ""

    # --- MeshCentral ---
    mesh_url: str = ""            # e.g. wss://remote.northernfruit.com
    mesh_user: str = ""
    mesh_password: str = ""
    mesh_token: str = ""         # optional login token (for 2FA accounts)
    mesh_verify_tls: bool = True

    @property
    def subnet_list(self) -> list[str]:
        return [s.strip() for s in self.subnets.split(",") if s.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
