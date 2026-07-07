#!/usr/bin/env python3
"""
netinv - a small agentless network inventory collector.

Usage:
  python netinv.py scan     --config config.yaml      # discover + collect
  python netinv.py list     [--db inventory.db]        # show what's stored
  python netinv.py software [--top 30 | --find chrome] # software rollup
  python netinv.py export   --format csv|json          # dump the inventory

This is a foundation, not a finished Lansweeper replacement. It shows the
mechanics of agentless collection and gives you a database to build on.
"""
import argparse
import concurrent.futures as cf
import csv
import json
import sys

import yaml

import ad
import discovery
import collectors
import store


def load_config(path):
    with open(path) as f:
        return yaml.safe_load(f)


def _collect_one(host, creds, want_software=False):
    """Run the right agentless collector(s) for one live host. Thread-safe:
    does network I/O only and returns data; the caller does all DB writes."""
    ip, tags = host["ip"], host["tags"]
    raws, norm = [], None
    software, sw_source = None, None
    if "windows" in tags and creds.get("windows"):
        norm, raw = collectors.collect_windows(ip, creds["windows"])
        raws.append(("winrm", raw))
        if want_software:
            software, meta = collectors.collect_windows_software(ip, creds["windows"])
            sw_source = "winrm"
            raws.append(("winrm-software", meta))
    if not norm and "linux" in tags and creds.get("linux"):
        norm, raw = collectors.collect_linux(ip, creds["linux"])
        raws.append(("ssh", raw))
        if want_software:
            software, meta = collectors.collect_linux_software(ip, creds["linux"])
            sw_source = "ssh"
            raws.append(("ssh-software", meta))
    # Try SNMP on anything still unidentified - switches, printers, firewalls,
    # SNMP-enabled servers (your Ubiquiti/MikroTik gear lands here). No software
    # inventory for these - firmware version comes through as os_name instead.
    if not norm and creds.get("snmp"):
        norm, raw = collectors.collect_snmp(ip, creds["snmp"])
        raws.append(("snmp", raw))
    return ip, host, norm, raws, software, sw_source


def cmd_scan(args):
    cfg = load_config(args.config)
    db = cfg.get("database", "inventory.db")
    creds = cfg.get("credentials", {})

    with store.connect(db) as conn:
        # --- 1. Seed from Active Directory (authoritative "should exist") ----
        ad_meta = None
        if cfg.get("active_directory"):
            print("[*] Enumerating computer objects from Active Directory...")
            try:
                computers, ad_meta = ad.collect_ad_computers(cfg["active_directory"])
                seeded = 0
                for c in computers:
                    if c["ip"]:                       # resolved to a live IP key
                        store.upsert_device(
                            conn, c["ip"], hostname=c["hostname"],
                            device_type="windows", in_ad=1,
                            ad_os=c["ad_os"], ad_last_logon=c["ad_last_logon"])
                        seeded += 1
                print(f"[*] AD: {ad_meta['total']} computer objects, "
                      f"{seeded} resolved in DNS, "
                      f"{ad_meta['unresolved_dns']} stale (no DNS record).")
            except Exception as e:
                print(f"[!] AD enumeration failed: {e}")

        # --- 2. Discover what's actually alive on the wire -----------------
        cidrs = cfg["subnets"]
        print(f"[*] Discovering hosts on {len(cidrs)} subnet(s)...")
        hosts = discovery.discover(
            cidrs,
            timeout=cfg.get("discovery", {}).get("timeout", 0.6),
            concurrency=cfg.get("discovery", {}).get("concurrency", 256),
        )
        print(f"[*] {len(hosts)} live host(s) responded on a probed port.")
        if not discovery.nmap_available():
            print("[i] nmap not found - add it for OS fingerprinting of odd devices.")

        for h in hosts:
            store.upsert_device(conn, h["ip"], mac=h["mac"], responded=1)
            store.add_raw(conn, h["ip"], "discovery", h)
            for p in h["open_ports"]:
                proto, hint, _ = discovery.PROBE_PORTS[p]
                store.add_port(conn, h["ip"], p, proto, hint)

        # --- 3. Collect facts in parallel (I/O bound -> threads) -----------
        coll = cfg.get("collection", {})
        workers = coll.get("workers", 20)
        want_sw = coll.get("software", False)
        sw_rows = 0
        print(f"[*] Collecting facts from {len(hosts)} host(s) "
              f"with {workers} workers"
              f"{' (incl. software)' if want_sw else ''}...")
        with cf.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(_collect_one, h, creds, want_sw) for h in hosts]
            for fut in cf.as_completed(futures):
                ip, host, norm, raws, software, sw_source = fut.result()
                for collector_name, raw in raws:
                    store.add_raw(conn, ip, collector_name, raw)
                if software:
                    store.sync_software(conn, ip, software, sw_source)
                    sw_rows += len(software)
                sw_note = f"  [{len(software)} apps]" if software else ""
                if norm:
                    store.upsert_device(conn, ip, **norm)
                    print(f"    {ip:<15} -> {norm.get('device_type'):<8} "
                          f"{norm.get('hostname') or ''} "
                          f"{norm.get('vendor') or ''} "
                          f"{norm.get('model') or ''}{sw_note}".rstrip())
                else:
                    store.upsert_device(conn, ip, device_type="unknown")
                    print(f"    {ip:<15} -> unknown  (ports: "
                          f"{','.join(map(str, host['open_ports']))})")
        if want_sw:
            print(f"[*] Software: recorded {sw_rows} installed package(s).")

        # --- 4. Reconcile ---------------------------------------------------
        def count(where):
            return conn.execute(f"SELECT COUNT(*) FROM devices WHERE {where}").fetchone()[0]
        silent = count("in_ad=1 AND responded=0")
        unmanaged = count("in_ad=0 AND responded=1")
        print("\n[=] Reconciliation")
        print(f"    in AD, answered on network : {count('in_ad=1 AND responded=1')}")
        print(f"    in AD, silent (off/stale?) : {silent}")
        print(f"    on network, not a domain PC: {unmanaged}"
              "  (printers, net gear, IoT, or unmanaged)")
    print(f"\n[*] Done. Stored in {db}")


def cmd_list(args):
    with store.connect(args.db) as conn:
        rows = conn.execute(
            "SELECT ip, mac, hostname, device_type, vendor, model, serial, "
            "os_name, last_seen FROM devices ORDER BY device_type, ip").fetchall()
    if not rows:
        print("(empty - run `scan` first)")
        return
    for r in rows:
        print(f"{r['ip']:<15} {r['device_type'] or '?':<8} "
              f"{(r['hostname'] or ''):<24} {(r['vendor'] or ''):<10} "
              f"{(r['model'] or ''):<18} {r['serial'] or ''}")


def cmd_software(args):
    """Fleet software rollup (default) or find every host running a package."""
    with store.connect(args.db) as conn:
        if args.find:
            rows = conn.execute(
                "SELECT s.name, s.version, s.ip, d.hostname "
                "FROM software s LEFT JOIN devices d ON d.ip = s.ip "
                "WHERE s.name LIKE ? ORDER BY s.name, d.hostname",
                (f"%{args.find}%",)).fetchall()
            if not rows:
                print("(no matches)")
                return
            for r in rows:
                who = r["hostname"] or r["ip"]
                print(f"{who:<24} {r['name']:<45} {r['version'] or ''}")
        else:
            rows = conn.execute(
                "SELECT name, COUNT(DISTINCT ip) AS installs "
                "FROM software GROUP BY name "
                "ORDER BY installs DESC, name LIMIT ?", (args.top,)).fetchall()
            if not rows:
                print("(no software yet - scan with `collection.software: true`)")
                return
            print(f"{'installs':>8}  software")
            for r in rows:
                print(f"{r['installs']:>8}  {r['name']}")


def cmd_export(args):
    with store.connect(args.db) as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM devices")]
    if args.format == "json":
        json.dump(rows, sys.stdout, indent=2, default=str)
        print()
    else:
        if not rows:
            print("(empty)")
            return
        w = csv.DictWriter(sys.stdout, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)


def main():
    ap = argparse.ArgumentParser(description="Agentless network inventory")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="discover and collect")
    s.add_argument("--config", default="config.yaml")
    s.set_defaults(func=cmd_scan)

    l = sub.add_parser("list", help="print stored devices")
    l.add_argument("--db", default="inventory.db")
    l.set_defaults(func=cmd_list)

    sw = sub.add_parser("software", help="software rollup, or --find a package")
    sw.add_argument("--db", default="inventory.db")
    sw.add_argument("--top", type=int, default=30,
                    help="how many packages in the rollup (default 30)")
    sw.add_argument("--find", help="list every host with a matching package")
    sw.set_defaults(func=cmd_software)

    e = sub.add_parser("export", help="dump inventory")
    e.add_argument("--db", default="inventory.db")
    e.add_argument("--format", choices=["csv", "json"], default="csv")
    e.set_defaults(func=cmd_export)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
