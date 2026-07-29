"""Agentless Windows inventory via WMI over DCOM (impacket).

Given a host and domain credentials, pulls OS, hardware, BIOS, CPU, memory,
disks, network adapters, logged-on user, antivirus status, and installed
software. Runs entirely without an agent on the target.

Requirements on the target: the account must have DCOM/WMI remote access
(typically a domain admin or a dedicated account granted WMI + "Remote
Enable"), and the host must be reachable on TCP 135 + the dynamic RPC range.

NOTE: This module is synchronous/blocking (impacket). The orchestrator runs it
in a thread pool executor.
"""
from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger("netview.wmi")

HKLM = 0x80000002
UNINSTALL_PATHS = [
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
]


def _val(props: dict, key: str):
    meta = props.get(key)
    if isinstance(meta, dict):
        return meta.get("value")
    return meta


def _row_props(record) -> dict:
    """impacket record -> {prop: value}."""
    out = {}
    for name, meta in record.getProperties().items():
        out[name] = meta.get("value") if isinstance(meta, dict) else meta
    return out


def _query(services, wql: str) -> list[dict]:
    rows: list[dict] = []
    try:
        it = services.ExecQuery(wql)
    except Exception as exc:
        log.debug("WMI query failed (%s): %s", wql, exc)
        return rows
    while True:
        try:
            rec = it.Next(0xFFFFFFFF, 1)[0]
        except Exception as exc:
            if "S_FALSE" in str(exc):
                break
            log.debug("WMI enum error (%s): %s", wql, exc)
            break
        rows.append(_row_props(rec))
    try:
        it.RemRelease()
    except Exception:
        pass
    return rows


def _software_via_registry(services) -> list[dict]:
    """Enumerate installed software from the Uninstall registry hives via
    the StdRegProv WMI provider. This is fast and avoids Win32_Product's known
    side effects (MSI reconfiguration)."""
    software: list[dict] = []
    try:
        reg, _ = services.GetObject("StdRegProv")
    except Exception as exc:
        log.debug("StdRegProv unavailable: %s", exc)
        return software

    for base in UNINSTALL_PATHS:
        try:
            enum = reg.EnumKey(HKLM, base)
            names = _val(enum.getProperties(), "sNames") or []
        except Exception as exc:
            log.debug("EnumKey failed for %s: %s", base, exc)
            continue
        for sub in names:
            keypath = f"{base}\\{sub}"
            try:
                dn = reg.GetStringValue(HKLM, keypath, "DisplayName")
                name = _val(dn.getProperties(), "sValue")
                if not name:
                    continue
                ver = _val(reg.GetStringValue(HKLM, keypath, "DisplayVersion").getProperties(), "sValue")
                pub = _val(reg.GetStringValue(HKLM, keypath, "Publisher").getProperties(), "sValue")
                software.append({"name": name, "version": ver, "publisher": pub})
            except Exception:
                continue
    # de-dup by (name, version)
    seen = set()
    deduped = []
    for s in software:
        key = (s["name"], s.get("version"))
        if key not in seen:
            seen.add(key)
            deduped.append(s)
    return sorted(deduped, key=lambda x: (x["name"] or "").lower())


def _software_via_win32product(services) -> list[dict]:
    rows = _query(services, "SELECT Name, Version, Vendor FROM Win32_Product")
    out = [{"name": r.get("Name"), "version": r.get("Version"), "publisher": r.get("Vendor")}
           for r in rows if r.get("Name")]
    return sorted(out, key=lambda x: (x["name"] or "").lower())


def probe(
    host: str,
    domain: str,
    username: str,
    password: str,
    software_inventory: str = "registry",
    timeout: int = 30,
) -> dict[str, Any]:
    """Collect Windows detail. Returns {} on connection failure, else a dict
    with an "_ok" flag. Never raises."""
    from impacket.dcerpc.v5.dcom import wmi
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
    from impacket.dcerpc.v5.dtypes import NULL

    result: dict[str, Any] = {"_ok": False}
    dcom = None
    try:
        dcom = DCOMConnection(
            host, username, password, domain, "", "", None, oxidResolver=True, doKerberos=False
        )
        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
        login = wmi.IWbemLevel1Login(iInterface)
        services = login.NTLMLogin("//./root/cimv2", NULL, NULL)
        login.RemRelease()

        os_rows = _query(services, "SELECT * FROM Win32_OperatingSystem")
        cs_rows = _query(services, "SELECT * FROM Win32_ComputerSystem")
        bios_rows = _query(services, "SELECT * FROM Win32_BIOS")
        csp_rows = _query(services, "SELECT * FROM Win32_ComputerSystemProduct")
        cpu_rows = _query(services, "SELECT Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed FROM Win32_Processor")
        disk_rows = _query(services, "SELECT DeviceID, Size, FreeSpace, VolumeName, FileSystem FROM Win32_LogicalDisk WHERE DriveType = 3")
        net_rows = _query(services, "SELECT Description, MACAddress, IPAddress, DefaultIPGateway, DHCPEnabled FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE")

        os0 = os_rows[0] if os_rows else {}
        cs0 = cs_rows[0] if cs_rows else {}
        bios0 = bios_rows[0] if bios_rows else {}
        csp0 = csp_rows[0] if csp_rows else {}

        result["os"] = {
            "caption": os0.get("Caption"),
            "version": os0.get("Version"),
            "build": os0.get("BuildNumber"),
            "architecture": os0.get("OSArchitecture"),
            "install_date": os0.get("InstallDate"),
            "last_boot": os0.get("LastBootUpTime"),
            "serial": os0.get("SerialNumber"),
            "registered_user": os0.get("RegisteredUser"),
        }
        result["computer"] = {
            "name": cs0.get("DNSHostName") or cs0.get("Name"),
            "manufacturer": cs0.get("Manufacturer"),
            "model": cs0.get("Model"),
            "domain": cs0.get("Domain"),
            "part_of_domain": cs0.get("PartOfDomain"),
            "system_type": cs0.get("SystemType"),
            "logged_on_user": cs0.get("UserName"),
            "total_memory_bytes": cs0.get("TotalPhysicalMemory"),
            "num_processors": cs0.get("NumberOfProcessors"),
        }
        result["bios"] = {
            "manufacturer": bios0.get("Manufacturer"),
            "version": bios0.get("SMBIOSBIOSVersion"),
            "serial": bios0.get("SerialNumber"),
            "release_date": bios0.get("ReleaseDate"),
        }
        result["product"] = {
            "vendor": csp0.get("Vendor"),
            "name": csp0.get("Name"),
            "serial": csp0.get("IdentifyingNumber"),
            "uuid": csp0.get("UUID"),
        }
        result["cpu"] = [
            {
                "name": c.get("Name"),
                "cores": c.get("NumberOfCores"),
                "threads": c.get("NumberOfLogicalProcessors"),
                "max_mhz": c.get("MaxClockSpeed"),
            }
            for c in cpu_rows
        ]
        result["disks"] = [
            {
                "device": d.get("DeviceID"),
                "label": d.get("VolumeName"),
                "fs": d.get("FileSystem"),
                "size_bytes": int(d["Size"]) if d.get("Size") else None,
                "free_bytes": int(d["FreeSpace"]) if d.get("FreeSpace") else None,
            }
            for d in disk_rows
        ]
        adapters = []
        for n in net_rows:
            ips = n.get("IPAddress") or []
            if isinstance(ips, str):
                ips = [ips]
            adapters.append({
                "description": n.get("Description"),
                "mac": (n.get("MACAddress") or "").upper() or None,
                "ips": list(ips),
                "gateway": n.get("DefaultIPGateway"),
                "dhcp": n.get("DHCPEnabled"),
            })
        result["adapters"] = adapters

        # Antivirus status from the SecurityCenter2 namespace (best-effort)
        try:
            av_login = wmi.IWbemLevel1Login(
                dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            )
            av_services = av_login.NTLMLogin("//./root/SecurityCenter2", NULL, NULL)
            av_login.RemRelease()
            av_rows = _query(av_services, "SELECT displayName, productState FROM AntiVirusProduct")
            result["antivirus"] = [{"name": a.get("displayName"), "state": a.get("productState")} for a in av_rows]
        except Exception as exc:
            log.debug("AV query failed on %s: %s", host, exc)
            result["antivirus"] = []

        # Software inventory
        if software_inventory == "registry":
            result["software"] = _software_via_registry(services)
        elif software_inventory == "win32product":
            result["software"] = _software_via_win32product(services)
        else:
            result["software"] = []

        result["_ok"] = True
    except Exception as exc:
        result["_error"] = str(exc)
        log.info("WMI probe failed on %s: %s", host, exc)
    finally:
        if dcom is not None:
            try:
                dcom.disconnect()
            except Exception:
                pass
    return result
