"""
collectors.py - the agentless data-gathering, one function per access method.

  collect_snmp   -> switches, routers, firewalls, printers, UPS, many servers
  collect_linux  -> Linux/Unix over SSH (dmidecode/lshw/etc.)
  collect_windows-> Windows over WinRM (CIM/WMI via PowerShell)

Each returns (normalized_dict, raw_dict). normalized keys line up with the
`devices` table; raw is the full harvest for raw_facts.

Credentials are passed in from config. See README for the security note - do
NOT ship plaintext creds to prod; use SSH keys, a vault, or per-site accounts.
"""
import json
import re
import shutil
import subprocess

# ---------------------------------------------------------------------------
# SNMP  (shells out to net-snmp: rock-solid, supports v1/v2c/v3)
#   Debian/Ubuntu: apt install snmp      RHEL: dnf install net-snmp-utils
# ---------------------------------------------------------------------------
SNMP_OIDS = {
    "sysDescr":    "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysName":     "1.3.6.1.2.1.1.5.0",
    "sysContact":  "1.3.6.1.2.1.1.4.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    # entPhysical: serial + model of the chassis (unit 1 varies by vendor,
    # so we walk and take the first non-empty in the orchestrator if needed)
    "serial":      "1.3.6.1.2.1.47.1.1.1.1.11",
    "model":       "1.3.6.1.2.1.47.1.1.1.1.13",
}


def _snmp_args(cfg):
    """Build the net-snmp auth flags for v2c or v3 from a config dict."""
    if cfg.get("version") == "3":
        args = ["-v3", "-l", cfg.get("level", "authPriv"),
                "-u", cfg["user"]]
        if cfg.get("auth_proto"):
            args += ["-a", cfg["auth_proto"], "-A", cfg["auth_key"]]
        if cfg.get("priv_proto"):
            args += ["-x", cfg["priv_proto"], "-X", cfg["priv_key"]]
        return args
    return ["-v2c", "-c", cfg.get("community", "public")]


def collect_snmp(ip, cfg, timeout=3):
    if not shutil.which("snmpget"):
        return None, {"error": "net-snmp not installed (apt install snmp)"}
    raw = {}
    for name, oid in SNMP_OIDS.items():
        cmd = (["snmpget", "-On", "-Oqv", "-t", str(timeout), "-r", "1"]
               + _snmp_args(cfg) + [ip, oid])
        try:
            out = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=timeout + 2)
        except subprocess.TimeoutExpired:
            continue
        val = out.stdout.strip().strip('"')
        if out.returncode == 0 and val and "No Such" not in val:
            raw[name] = val
    if not raw:
        return None, {}
    descr = raw.get("sysDescr", "")
    norm = {
        "device_type": "network",
        "hostname": raw.get("sysName"),
        "serial": raw.get("serial"),
        "model": raw.get("model"),
        "vendor": _vendor_from_descr(descr),
        "os_name": descr[:120] or None,
        "source": "snmp",
    }
    return norm, raw


def _vendor_from_descr(descr):
    d = descr.lower()
    for key, name in [("cisco", "Cisco"), ("arista", "Arista"),
                      ("juniper", "Juniper"), ("aruba", "Aruba"),
                      ("hp ", "HP"), ("hewlett", "HP"), ("ubiquiti", "Ubiquiti"),
                      ("mikrotik", "MikroTik"), ("fortinet", "Fortinet"),
                      ("palo alto", "Palo Alto"), ("dell", "Dell"),
                      ("brocade", "Brocade"), ("netgear", "Netgear")]:
        if key in d:
            return name
    return None


# ---------------------------------------------------------------------------
# Linux / Unix over SSH  (paramiko)
# ---------------------------------------------------------------------------
LINUX_CMDS = {
    "hostname":  "hostname -f 2>/dev/null || hostname",
    "os":        "cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'",
    "kernel":    "uname -r",
    "product":   "cat /sys/class/dmi/id/product_name 2>/dev/null",
    "vendor":    "cat /sys/class/dmi/id/sys_vendor 2>/dev/null",
    "serial":    "cat /sys/class/dmi/id/product_serial 2>/dev/null",
    "cpu":       "lscpu 2>/dev/null | grep 'Model name' | head -1 | cut -d: -f2 | xargs",
    "cores":     "nproc",
    "mem_kb":    "grep MemTotal /proc/meminfo | awk '{print $2}'",
    "disks":     "lsblk -dno NAME,SIZE,MODEL 2>/dev/null",
}


def collect_linux(ip, cfg, timeout=8):
    try:
        import paramiko
    except ImportError:
        return None, {"error": "paramiko not installed"}
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kw = dict(hostname=ip, username=cfg["user"], timeout=timeout,
                      allow_agent=False, look_for_keys=False)
    if cfg.get("key_file"):
        connect_kw["key_filename"] = cfg["key_file"]
    else:
        connect_kw["password"] = cfg.get("password")
    raw = {}
    try:
        client.connect(**connect_kw)
        for name, cmd in LINUX_CMDS.items():
            _, out, _ = client.exec_command(cmd, timeout=timeout)
            raw[name] = out.read().decode(errors="replace").strip()
    except Exception as e:
        return None, {"error": str(e)}
    finally:
        client.close()

    mem_mb = None
    if raw.get("mem_kb", "").isdigit():
        mem_mb = int(raw["mem_kb"]) // 1024
    norm = {
        "device_type": "linux",
        "hostname": raw.get("hostname") or None,
        "os_name": raw.get("os") or None,
        "vendor": raw.get("vendor") or None,
        "model": raw.get("product") or None,
        "serial": raw.get("serial") or None,
        "cpu": raw.get("cpu") or None,
        "memory_mb": mem_mb,
        "source": "ssh",
    }
    return norm, raw


# ---------------------------------------------------------------------------
# Windows over WinRM  (pywinrm) - the sanctioned agentless path.
#   Enable fleet-wide via GPO, or per-host: winrm quickconfig
# ---------------------------------------------------------------------------
WIN_PS = r"""
$ErrorActionPreference='SilentlyContinue'
$cs = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
$bios = Get-CimInstance Win32_BIOS
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
[PSCustomObject]@{
  hostname     = $cs.DNSHostName
  domain       = $cs.Domain
  vendor       = $cs.Manufacturer
  model        = $cs.Model
  serial       = $bios.SerialNumber
  os_name      = $os.Caption
  os_version   = $os.Version
  cpu          = $cpu.Name
  memory_mb    = [math]::Round($cs.TotalPhysicalMemory/1MB)
} | ConvertTo-Json -Compress
"""


def collect_windows(ip, cfg, timeout=15):
    try:
        import winrm
    except ImportError:
        return None, {"error": "pywinrm not installed"}
    transport = cfg.get("transport", "ntlm")   # ntlm | kerberos | basic
    scheme = "https" if cfg.get("use_ssl") else "http"
    port = cfg.get("port", 5986 if cfg.get("use_ssl") else 5985)
    try:
        session = winrm.Session(
            f"{scheme}://{ip}:{port}/wsman",
            auth=(cfg["user"], cfg["password"]),
            transport=transport,
            server_cert_validation="ignore",
        )
        r = session.run_ps(WIN_PS)
    except Exception as e:
        return None, {"error": str(e)}
    if r.status_code != 0:
        return None, {"error": r.std_err.decode(errors="replace")[:300]}
    try:
        raw = json.loads(r.std_out.decode(errors="replace") or "{}")
    except json.JSONDecodeError:
        return None, {"error": "unparseable WinRM output"}
    norm = {
        "device_type": "windows",
        "hostname": raw.get("hostname"),
        "vendor": raw.get("vendor"),
        "model": raw.get("model"),
        "serial": raw.get("serial"),
        "os_name": raw.get("os_name"),
        "cpu": raw.get("cpu"),
        "memory_mb": raw.get("memory_mb"),
        "source": "winrm",
    }
    return norm, raw


# ---------------------------------------------------------------------------
# Software inventory
#
# Windows: read the registry Uninstall keys - the same list you see in
# "Programs and Features". We deliberately do NOT use Win32_Product: querying
# that class triggers an MSI self-repair/consistency check on every installed
# package, which is slow and floods the event log. The registry is fast and
# side-effect-free.
#
# Note: this reads the machine-wide (HKLM) hives, which covers all-users
# installs. Per-user (HKCU) installs live in each loaded user hive and need
# extra work to enumerate agentlessly - a documented next step, not done here.
# ---------------------------------------------------------------------------
WIN_SOFTWARE_PS = r"""
$ErrorActionPreference='SilentlyContinue'
$paths=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
         'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
$apps = Get-ItemProperty $paths |
  Where-Object { $_.DisplayName -and -not $_.SystemComponent } |
  Select-Object @{n='name';e={$_.DisplayName}},
                @{n='version';e={$_.DisplayVersion}},
                @{n='publisher';e={$_.Publisher}},
                @{n='install_date';e={$_.InstallDate}} |
  Sort-Object name -Unique
@($apps) | ConvertTo-Json -Compress
"""


def _fmt_install_date(v):
    if not v:
        return None
    v = str(v).strip()
    if len(v) == 8 and v.isdigit():          # registry 'YYYYMMDD' -> ISO
        return f"{v[0:4]}-{v[4:6]}-{v[6:8]}"
    return v or None


def _parse_software_json(text):
    text = (text or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):               # single result isn't wrapped
        data = [data]
    out = []
    for d in data:
        name = (d.get("name") or "").strip()
        if not name:
            continue
        out.append({
            "name": name,
            "version": (d.get("version") or None),
            "publisher": (d.get("publisher") or None),
            "install_date": _fmt_install_date(d.get("install_date")),
        })
    return out


def collect_windows_software(ip, cfg, timeout=30):
    """Return (packages, meta). packages: list of {name,version,publisher,install_date}."""
    try:
        import winrm
    except ImportError:
        return [], {"error": "pywinrm not installed"}
    scheme = "https" if cfg.get("use_ssl") else "http"
    port = cfg.get("port", 5986 if cfg.get("use_ssl") else 5985)
    try:
        session = winrm.Session(
            f"{scheme}://{ip}:{port}/wsman",
            auth=(cfg["user"], cfg["password"]),
            transport=cfg.get("transport", "ntlm"),
            server_cert_validation="ignore",
        )
        r = session.run_ps(WIN_SOFTWARE_PS)
    except Exception as e:
        return [], {"error": str(e)}
    if r.status_code != 0:
        return [], {"error": r.std_err.decode(errors="replace")[:300]}
    pkgs = _parse_software_json(r.std_out.decode(errors="replace"))
    return pkgs, {"count": len(pkgs)}


# Linux: ask the package manager directly. dpkg for Debian/Ubuntu, rpm for
# RHEL/Rocky/SUSE. Version includes the release for rpm.
LINUX_SOFTWARE_CMD = (
    "if command -v dpkg-query >/dev/null 2>&1; then "
    "dpkg-query -W -f='${Package}\\t${Version}\\n'; "
    "elif command -v rpm >/dev/null 2>&1; then "
    "rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n'; fi"
)


def collect_linux_software(ip, cfg, timeout=20):
    try:
        import paramiko
    except ImportError:
        return [], {"error": "paramiko not installed"}
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kw = dict(hostname=ip, username=cfg["user"], timeout=timeout,
              allow_agent=False, look_for_keys=False)
    if cfg.get("key_file"):
        kw["key_filename"] = cfg["key_file"]
    else:
        kw["password"] = cfg.get("password")
    pkgs = []
    try:
        client.connect(**kw)
        _, out, _ = client.exec_command(LINUX_SOFTWARE_CMD, timeout=timeout)
        for line in out.read().decode(errors="replace").splitlines():
            if "\t" in line:
                name, ver = line.split("\t", 1)
                if name.strip():
                    pkgs.append({"name": name.strip(),
                                 "version": ver.strip() or None,
                                 "publisher": None, "install_date": None})
    except Exception as e:
        return [], {"error": str(e)}
    finally:
        client.close()
    return pkgs, {"count": len(pkgs)}
