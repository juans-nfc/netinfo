# NetView

An agentless network inventory tool — a self-hosted, Dockerized alternative to
Lansweeper for a small-to-mid AD estate. It discovers everything on your
network with **no agent installed on the targets**, pulls as much detail as it
can out of each device, correlates the results against your MeshCentral agents,
and presents it all in a searchable web console.

Built for the typical flat setup: one domain, ~100 machines, a few sites joined
over site-to-site VPN.

---

## What it collects

| Source | How | What you get |
|---|---|---|
| **nmap** | ICMP/ARP/port scan + service & OS detection | live hosts, MAC + vendor, reverse-DNS + NetBIOS name, open ports with service/product/version, OS family guess |
| **WMI** (Windows) | impacket over DCOM, agentless | OS caption/version/build, manufacturer/model/serial, BIOS, CPU, RAM, disks, network adapters, logged-on user, antivirus status, **installed software inventory** |
| **SNMP** | v2c/v1 community | switches, routers, printers, UPSs — sysDescr/name/location, interface count, printer page counts |
| **SSH** (Linux/Unix/macOS) | paramiko, password or key | OS/kernel/arch, CPU/RAM, product/serial, uptime, root disk usage |
| **MeshCentral** | WebSocket control API | which assets have a managed agent, agent online/offline, agent-reported OS, and a deep link straight to the device in MeshCentral |

Everything is keyed on MAC address where available (falling back to IP), so a
device keeps one record across scans even when its IP changes.

---

## Architecture

```
                          ┌─────────────────────────────────────────┐
   Browser ── /netinfo ──▶│ nginx (tools.northernfruit.com)          │
                          └───────────────┬─────────────────────────┘
                                          │ proxy_pass 127.0.0.1:8850
                          ┌───────────────▼─────────────────────────┐
                          │ NetView (FastAPI, host networking)       │
                          │  ├─ nmap discovery ─────────┐            │
                          │  ├─ WMI / SNMP / SSH probes  │ per host   │
                          │  ├─ MeshCentral correlation ─┘            │
                          │  ├─ SQLite (/app/data)                    │
                          │  └─ web UI (vanilla JS)                   │
                          └──────┬──────────────────────┬────────────┘
                     scans local + VPN subnets     wss://remote.northernfruit.com
```

The scanner runs on the host network so it can reach all three sites over the
VPN and read MACs off the local segment.

---

## Quick start

```bash
git clone <this repo> netview && cd netview
./deploy.sh
```

`deploy.sh` is the one-command deploy: it creates `.env` from the example on
first run, generates `NETVIEW_SECRET_KEY` for you if it's blank, builds the
image, starts the stack, and waits for the health check to pass before
reporting success. Re-run it any time to redeploy. Other subcommands:

```bash
./deploy.sh status     # container + health status
./deploy.sh logs       # follow logs
./deploy.sh rollback   # revert to the previous image (kept automatically)
./deploy.sh down       # stop the stack
```

Before your first scan, open `.env` (or the UI **Settings** tab) to set your
subnets and MeshCentral credentials:

```bash
nano .env && ./deploy.sh    # re-run to apply .env changes
```

If you'd rather drive compose directly, `docker compose up -d --build` still
works.

Then wire it into nginx on `tools.northernfruit.com` — copy the block from
[`nginx-netview.conf.example`](./nginx-netview.conf.example) into that server
block and reload:

```bash
nginx -t && systemctl reload nginx
```

Open **https://tools.northernfruit.com/netinfo/**, go to **Settings** to confirm
your subnets and MeshCentral connection, add scan credentials under
**Credentials**, then hit **Run scan**.

> **First run tip:** before nginx is configured you can reach it directly on the
> server at `http://<server-ip>:8850/` to get set up.

### Generate a secret key

`NETVIEW_SECRET_KEY` encrypts stored scan credentials at rest. Set it to a
stable random value — if it changes, saved credentials must be re-entered.

```bash
openssl rand -hex 32
```

---

## Networking

`docker-compose.yml` uses **`network_mode: host`** plus `NET_RAW`/`NET_ADMIN`.
That's the recommended mode because it lets the scanner:

- reach all three sites over the site-to-site VPN (the routes live on the host),
- read MAC addresses via ARP on the local L2 segment,
- run nmap SYN scans and OS fingerprinting.

If you can't use host networking (e.g. Docker Desktop on Windows/Mac for
testing), the compose file has a commented bridge-mode block. In bridge mode
ARP-based MAC discovery and OS detection are limited, but WMI/SNMP/SSH still
work as long as the container has routes to the remote subnets.

---

## Setting up scan credentials

Add these in the UI under **Credentials** (stored encrypted; never shown again
after saving). You can add several of each kind — NetView tries them in turn
per host until one authenticates.

### Windows (WMI)

Use a domain account with remote WMI access. A domain admin works out of the
box; for least privilege, create a dedicated account (e.g. `svc-netview`) and
grant it, on the target machines (usually via GPO):

- **DCOM** *Remote Activation*,
- **WMI namespace** `Root/CIMV2` — *Enable Account* + *Remote Enable* (and
  `Root/SecurityCenter2` if you want antivirus status),
- membership as needed so it can read the registry uninstall hives (for the
  software inventory).

Enter the domain in the **Domain** field (NetBIOS form, e.g. `NORTHERNFRUIT`)
and the username without the domain prefix.

Requirements on the host: reachable on **TCP 135** plus the dynamic RPC range
(or the fixed range if you've pinned WMI). The Windows firewall rule group is
*"Windows Management Instrumentation (WMI)"*.

### SNMP

Add the read-only community string (v2c). NetView reads the standard system
group, interface counts, and printer page counts.

### SSH (Linux/Unix)

Enter a username and either a password **or** paste a PEM private key into the
secret field (NetView auto-detects `-----BEGIN`). Commands run are read-only
(`uname`, `/etc/os-release`, `/proc/*`, `df`).

---

## MeshCentral integration

NetView talks to MeshCentral over the same WebSocket control API the web UI
uses (`/control.ashx`), so nothing extra needs enabling on the server.

Configure it under **Settings → MeshCentral** (or via `NETVIEW_MESH_*` in
`.env`):

- **Server URL** — `wss://remote.northernfruit.com`
- **Username / Password** — a MeshCentral account (a viewer-level account is
  enough; it only lists devices)
- **Verify TLS** — turn off only if the server uses a self-signed cert

Click **Test connection** to confirm — it reports the server name, node count,
and how many agents are online.

**If the account uses 2FA**, password login over the API won't work. Generate a
login token on the MeshCentral server and paste it into the **2FA login token**
field:

```bash
cd /opt/meshcentral   # or wherever MeshCentral lives
node node_modules/meshcentral/meshcentral --logintoken "user//<username>"
```

Correlation matches a scanned device to a Mesh node by hostname first, then IP.
Matched devices show a **mesh agent** chip in the list and an **Open in
MeshCentral** button in the detail drawer.

---

## Scheduled scans

Set a cron expression in `.env` to scan automatically:

```env
NETVIEW_SCAN_CRON=0 6 * * *     # every day at 06:00 (container timezone)
```

Leave it blank to disable. You can always trigger a scan manually from the UI.
Only one scan runs at a time; a scheduled run is skipped if a manual one is in
progress.

---

## Configuration reference (`.env`)

| Variable | Default | Notes |
|---|---|---|
| `NETVIEW_ROOT_PATH` | `` | **Leave empty** — the bundled nginx snippet strips the prefix and the UI uses relative URLs. Only set it if your nginx does *not* strip the prefix (see Troubleshooting) |
| `NETVIEW_PORT` | `8850` | Bind port (host networking) |
| `NETVIEW_SECRET_KEY` | *(none)* | **Set this.** Encrypts stored credentials |
| `NETVIEW_UI_USER` / `_PASSWORD` | *(none)* | Optional HTTP basic auth for the UI |
| `NETVIEW_SUBNETS` | `` | Comma-separated CIDRs; also editable in the UI |
| `NETVIEW_MAX_CONCURRENCY` | `24` | Parallel deep probes |
| `NETVIEW_PROBE_TIMEOUT` | `30` | Per-host probe timeout (s) |
| `NETVIEW_NMAP_TIMING` | `4` | nmap `-T` template (0–5) |
| `NETVIEW_NMAP_OS_DETECT` | `true` | nmap `-O`; needs raw sockets |
| `NETVIEW_WMI_SOFTWARE_INVENTORY` | `registry` | `registry` \| `win32product` \| `off` |
| `NETVIEW_SCAN_CRON` | `` | Cron for scheduled scans |
| `NETVIEW_MESH_URL` … | `` | MeshCentral connection |

Subnets and MeshCentral settings set in the UI are stored in the database and
override the `.env` values, so you can change targets without redeploying.

---

## Security notes

- Run NetView on a trusted internal network only. It holds domain credentials
  and detailed inventory — put it behind your existing nginx/auth and don't
  expose `:8850` publicly.
- Credentials are encrypted at rest with `NETVIEW_SECRET_KEY`. Keep that key
  out of source control (it's read from `.env`).
- Only ever scan networks you own and administer. NetView performs active
  scanning (port scans, service probes, authenticated logins).
- The `data/` volume contains the SQLite DB and encryption key — back it up and
  protect it like any credential store.

---

## Known limitations & things to verify in your environment

- **Windows software inventory** uses the `StdRegProv` WMI provider to read the
  Uninstall registry hives (in `app/scanner/wmi_probe.py`). This is the correct
  agentless approach and avoids `Win32_Product`'s side effects, but it's the one
  path that couldn't be tested against a live Windows host during development —
  validate it on your first scan of a real machine. If it misbehaves, set
  `NETVIEW_WMI_SOFTWARE_INVENTORY=win32product` to fall back to the (slower)
  `Win32_Product` class, or `off` to skip software collection. A failure here
  never aborts the rest of a host's inventory.
- **MeshCentral deep link** is built as `{server}/#p=devices&node={nodeid}`.
  The fragment format can vary slightly between MeshCentral versions; if the
  link doesn't focus the device, the node ID is still shown so you can adjust
  `device_link()` in `app/meshcentral.py`.
- Mesh correlation is by hostname then IP (good enough for a flat estate). MAC-
  based correlation would require an extra `getsysinfo` call per node.
- SQLite is used for storage — fine well past a few hundred devices. Swap the
  engine URL in `app/database.py` for Postgres if you ever outgrow it.

---

## Troubleshooting

**The page loads but has no styling; CSS/JS 404 under the sub-path**
(`GET /netinfo/static/style.css → 404`). The prefix is being handled twice.
The bundled nginx snippet **strips** the sub-path (its `proxy_pass` ends in a
trailing slash), so `NETVIEW_ROOT_PATH` must be **empty** — otherwise the app
looks for static files under a prefix nginx already removed. Fix: set
`NETVIEW_ROOT_PATH=` (empty) in `.env`, `./deploy.sh`, then hard-refresh the
browser (Ctrl/Cmd-Shift-R) to clear the cached 404s.

The two valid combinations are:

| nginx `proxy_pass` | `NETVIEW_ROOT_PATH` |
|---|---|
| `http://127.0.0.1:8850/` (trailing slash → strips prefix) — **the bundled snippet** | *empty* |
| `http://127.0.0.1:8850` (no trailing slash → keeps prefix) | `/netinfo` |

Mixing them (prefix set **and** stripped) is the cause of the 404 above.

## Development (without Docker)

```bash
pip install -r requirements.txt
apt-get install nmap                      # discovery engine
export NETVIEW_DATA_DIR=./data NETVIEW_SECRET_KEY=dev
uvicorn app.main:app --reload --port 8850
```

Raw-socket scans (SYN, `-O`, ARP) need root or `CAP_NET_RAW`+`CAP_NET_ADMIN`.

API docs are auto-generated at `/<root_path>/docs`.

## Project layout

```
app/
  main.py            FastAPI app, static serving, lifespan
  config.py          env-driven settings
  database.py        SQLAlchemy engine (SQLite)
  models.py          Device / ScanRun / Credential / Setting
  crypto.py          Fernet credential encryption
  runtime.py         effective subnets + mesh config (DB overrides env)
  scan_manager.py    single-scan guard + live progress
  scheduler.py       APScheduler cron scans
  meshcentral.py     MeshCentral WebSocket client + correlation
  scanner/
    discovery.py     nmap wrapper + XML parsing
    wmi_probe.py     agentless Windows via impacket WMI
    snmp_probe.py    SNMP (pysnmp)
    ssh_probe.py     SSH (paramiko)
    oui.py           MAC vendor lookup
    orchestrator.py  the full scan pipeline
  api/               REST routes (devices, scan, credentials, settings)
  static/            web UI (index.html, style.css, app.js)
```
