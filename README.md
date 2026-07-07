# netinv — agentless network inventory (starter)

A small, self-hosted collector that discovers devices on your networks and
pulls hardware/OS facts from them **without installing agents**. It's a
foundation you own and extend — not a drop-in Lansweeper clone.

## Quick start

```bash
git clone <your-repo-url> netinv && cd netinv
cp config.example.yaml config.yaml     # then edit: subnets + credentials
./deploy.sh                            # provisions everything, opens the UI
```

`deploy.sh` builds a venv, installs dependencies, initializes the database,
**finds a free port automatically** so it won't clash with anything already
running, and starts the web UI. Then open the URL it prints, click **Run scan**,
and the dashboards populate.

Prefer the command line? The collector runs on its own:

```bash
source .venv/bin/activate
python netinv.py scan --config config.yaml
python netinv.py list
python netinv.py software --find "Acrobat"
```

## Repo layout

```
netinv.py            CLI entry point (scan / list / software / export)
discovery.py         host discovery (TCP sweep, ARP, nmap hand-off)
collectors.py        agentless collectors: SNMP, SSH/Linux, WinRM/Windows, software
ad.py                Active Directory (LDAP) computer enumeration
store.py             SQLite storage + schema
app.py               Flask web UI (reads inventory.db, triggers scans)
templates/, static/  the dashboard front-end
deploy.sh            provision + free-port launcher + systemd unit generator
config.example.yaml  copy to config.yaml and fill in
```

## Web UI

`app.py` serves two live dashboards over `inventory.db`: the device inventory
with the AD reconciliation strip and a drill-down drawer (hardware, open ports,
installed software), and the fleet-wide software rollup with version-sprawl
badges and per-package host lists. A **Run scan** button launches a scan in the
background and the pages refresh when it finishes.

The `deploy.sh` script also writes a `netinv-web.service` systemd unit with the
chosen port baked in, so you can make it persistent:

```bash
sudo cp netinv-web.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now netinv-web
```

Run scans on a schedule with cron or a systemd timer, e.g. hourly:

```
0 * * * * cd /path/to/netinv && .venv/bin/python netinv.py scan --config config.yaml
```

## Security — read this before exposing the UI

- **The web UI has no authentication.** Bind it to localhost (`HOST=127.0.0.1
  ./deploy.sh`) and reach it over an SSH tunnel, or put it behind a reverse
  proxy that enforces auth, or firewall the port. Don't put it on an untrusted
  network as-is.
- `config.yaml` holds credentials and is **git-ignored** — keep it that way, and
  `chmod 600 config.yaml`. Prefer SSH keys, a read-only domain service account,
  and SNMPv3 over `public`.
- The database is also git-ignored; it contains your full inventory.

## How "agentless" works here

Different device classes speak different protocols, so there's no single magic
method — the tool routes each host to the right one:

| Device type                         | Method            | What it needs on the target |
|-------------------------------------|-------------------|-----------------------------|
| Windows desktops / servers          | WinRM (CIM/WMI)   | WinRM enabled (GPO) + admin/read acct |
| Linux / Unix servers                | SSH               | An SSH login (key preferred) |
| Switches, routers, firewalls, printers, UPS | SNMP v2c/v3 | SNMP enabled + community / v3 creds |
| Anything else                       | port fingerprint  | nothing (best-effort)        |

## Active Directory reconciliation (Windows/AD environments)

If you fill in the `active_directory:` block, `scan` first enumerates every
computer object from AD, then reconciles it against what the network scan
actually finds, and prints a summary:

```
[=] Reconciliation
    in AD, answered on network : 271
    in AD, silent (off/stale?) : 34
    on network, not a domain PC: 48   (printers, net gear, IoT, or unmanaged)
```

That third bucket is where surprises live. Enumerating computer objects only
needs a **read-only domain account** — no elevated rights.

## Software inventory

With `collection.software: true`, each Windows and Linux host is also polled for
its installed software over the same WinRM/SSH session:

- **Windows** — reads the registry Uninstall keys (the "Programs and Features"
  list). It deliberately avoids the `Win32_Product` WMI class, which triggers an
  MSI self-repair on every package as it enumerates — slow and it spams the
  event log. Covers all-users installs; per-user (HKCU) installs are a noted
  next step.
- **Linux** — queries the package manager directly (`dpkg` or `rpm`).

Each package is stored with a `first_seen` / `last_seen`, so you can tell what
newly appeared and (by a lagging `last_seen`) what's been uninstalled.

Report on it:

```bash
python netinv.py software                 # top installed packages, fleet-wide
python netinv.py software --top 60
python netinv.py software --find "Acrobat"  # every host running a package
```

That rollup is your license-count and "who still has the old version" view.

## Turning on the agentless access (one-time)

- **WinRM on every domain PC** — one GPO does it fleet-wide:
  *Computer Config → Policies → Admin Templates → Windows Components → Windows
  Remote Management (WinRM) → WinRM Service → Allow remote server management*,
  set the service to auto-start, and open TCP 5985/5986 in the firewall GPO.
  Grant your `svc-inventory` account remote WMI + WinRM (read) rights.
- **SNMP on Ubiquiti/MikroTik** — MikroTik: `/snmp set enabled=yes` and add a
  community (use SNMPv3 where the model supports it). Ubiquiti: enable SNMP in
  UniFi/EdgeMax settings. Bonus: the **UniFi Controller API** already tracks
  every client (MAC, IP, hostname, *and the switch port it's on*) — that's a
  superb discovery source to add alongside SNMP.

## Install

```bash
pip install -r requirements.txt          # paramiko, pywinrm, pyyaml, ldap3
sudo apt install snmp nmap               # net-snmp (SNMP) + nmap (optional)
cp config.example.yaml config.yaml       # then edit subnets + credentials
```

## Run

```bash
python netinv.py scan --config config.yaml
python netinv.py list
python netinv.py export --format csv > inventory.csv
```

## Reaching remote sites over the VPN

Discovery uses TCP connect + ping, which routes fine over a site-to-site VPN,
so a single collector can scan every subnet you list. Two caveats:

- **MAC addresses** only come from the collector's *local* ARP table. For
  remote subnets, read the site's L3 gateway's ARP table via SNMP instead
  (`1.3.6.1.2.1.4.22` / bridge MIB) — that also enumerates hosts you might miss.
  This is a great next feature and a standard trick.
- For lowest latency and fullest coverage you can run a lightweight collector
  at each site that reports back to one database.

## Security notes (please read)

- `config.yaml` holds credentials — keep it out of git and lock its permissions
  (`chmod 600`). Prefer **SSH keys**, environment variables, or a secrets vault
  over plaintext.
- Use **dedicated read-only service accounts**, not Domain Admin. Windows
  inventory needs only WMI read; SNMP should be **v3 authPriv**, not `public`.
- Scanning is noisy and may trip IDS/IPS. Tell your security team first and
  scan from an allow-listed host.

## Roadmap / where to take it next

1. **Dedupe by serial/MAC** so IP changes don't create duplicate assets.
2. **SNMP walks** for interfaces (`ifTable`), neighbors (LLDP/CDP → topology),
   and the gateway ARP trick above.
3. **Richer Windows/Linux facts** — installed software, disks, warranty lookup.
4. **Scheduling** (cron/systemd timer) + a change log (what appeared/vanished).
5. **A web UI or push into NetBox** if you want a real source of truth.

## Honest scope note

Building a full Lansweeper equivalent is mostly the *long tail*: normalizing
every vendor's SNMP MIBs, WMI quirks, OUI/vendor databases, warranty feeds.
For a small/medium estate this collector plus a few evenings of extension is
very workable. To fully replace Lansweeper's breadth, also weigh open-source
options: **NetBox** (+ these collectors feeding it), **GLPI + FusionInventory**,
**OCS Inventory**, or **Uyuni**.
