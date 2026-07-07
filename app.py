#!/usr/bin/env python3
"""
app.py - the netinv web UI.

Read-only dashboards over inventory.db (device inventory, AD reconciliation,
software rollup) plus a button that kicks off a scan in the background. Uses
the same store module and database the CLI collector writes to, so the UI is
always a live view of whatever the last scan produced.

Run standalone:  python app.py --host 0.0.0.0 --port 8080
Prod (1 worker): gunicorn -w 1 -b 0.0.0.0:8080 app:app
The deploy.sh script picks a free port automatically.

SECURITY: this app has no authentication and exposes your inventory. Bind it to
localhost and reach it over SSH, or put it behind a reverse proxy that handles
auth, or restrict it with a firewall. Do not expose it to untrusted networks.
"""
import datetime as dt
import os
import subprocess
import sys
import threading

from flask import Flask, abort, jsonify, render_template, request

import store

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get("NETINV_DB", os.path.join(BASE, "inventory.db"))
CONFIG = os.environ.get("NETINV_CONFIG", os.path.join(BASE, "config.yaml"))

app = Flask(__name__)

_scan = {"running": False, "started": None, "finished": None,
         "returncode": None, "log": ""}
_scan_lock = threading.Lock()


def _now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _rows(conn, sql, args=()):
    return [dict(r) for r in conn.execute(sql, args).fetchall()]


@app.route("/")
def devices_page():
    return render_template("devices.html", active="devices")


@app.route("/software")
def software_page():
    return render_template("software.html", active="software")


@app.route("/api/stats")
def api_stats():
    with store.connect(DB) as conn:
        def c(w):
            return conn.execute(f"SELECT COUNT(*) FROM devices WHERE {w}").fetchone()[0]
        stats = {
            "total": conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
            "ad_online": c("in_ad=1 AND responded=1"),
            "ad_silent": c("in_ad=1 AND responded=0"),
            "not_ad": c("in_ad=0 AND responded=1"),
            "unique_software": conn.execute(
                "SELECT COUNT(DISTINCT name) FROM software").fetchone()[0],
            "total_installs": conn.execute(
                "SELECT COUNT(*) FROM software").fetchone()[0],
            "last_scan": conn.execute(
                "SELECT MAX(last_seen) FROM devices").fetchone()[0],
        }
    return jsonify(stats)


@app.route("/api/devices")
def api_devices():
    with store.connect(DB) as conn:
        rows = _rows(conn,
            "SELECT ip,mac,hostname,device_type,vendor,model,serial,os_name,"
            "in_ad,responded,ad_os,ad_last_logon,last_seen "
            "FROM devices ORDER BY device_type, ip")
    for r in rows:
        r["status"] = ("online" if r["responded"]
                       else "silent" if r["in_ad"] else "unknown")
    return jsonify(rows)


@app.route("/api/device/<path:ip>")
def api_device(ip):
    with store.connect(DB) as conn:
        dev = _rows(conn, "SELECT * FROM devices WHERE ip=?", (ip,))
        if not dev:
            abort(404)
        d = dev[0]
        d["ports"] = _rows(conn,
            "SELECT port,proto,hint FROM open_ports WHERE ip=? ORDER BY port", (ip,))
        d["software"] = _rows(conn,
            "SELECT name,version,publisher,install_date,first_seen,last_seen "
            "FROM software WHERE ip=? ORDER BY name", (ip,))
    return jsonify(d)


@app.route("/api/software")
def api_software():
    top = int(request.args.get("top", 300))
    with store.connect(DB) as conn:
        rows = _rows(conn,
            "SELECT name, COUNT(DISTINCT ip) AS installs, "
            "COUNT(DISTINCT version) AS versions, MAX(publisher) AS publisher, "
            "MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen "
            "FROM software GROUP BY name ORDER BY installs DESC, name LIMIT ?",
            (top,))
    return jsonify(rows)


@app.route("/api/software/find")
def api_software_find():
    name = request.args.get("q", "")
    with store.connect(DB) as conn:
        rows = _rows(conn,
            "SELECT s.name, s.version, s.ip, d.hostname "
            "FROM software s LEFT JOIN devices d ON d.ip = s.ip "
            "WHERE s.name = ? ORDER BY s.version DESC, d.hostname", (name,))
    return jsonify(rows)


def _run_scan():
    with _scan_lock:
        _scan.update(running=True, started=_now(), finished=None,
                     returncode=None, log="")
    try:
        p = subprocess.run(
            [sys.executable, os.path.join(BASE, "netinv.py"), "scan",
             "--config", CONFIG],
            capture_output=True, text=True, cwd=BASE, timeout=7200)
        out, rc = (p.stdout or "") + (p.stderr or ""), p.returncode
    except Exception as e:
        out, rc = f"scan failed to launch: {e}", -1
    with _scan_lock:
        _scan.update(running=False, finished=_now(), returncode=rc,
                     log=out[-8000:])


@app.route("/api/scan", methods=["POST"])
def api_scan_start():
    with _scan_lock:
        if _scan["running"]:
            return jsonify({"status": "already_running"}), 409
    if not os.path.exists(CONFIG):
        return jsonify({"status": "no_config",
                        "detail": "config.yaml not found - copy the example "
                                  "and add credentials first"}), 400
    threading.Thread(target=_run_scan, daemon=True).start()
    return jsonify({"status": "started"})


@app.route("/api/scan", methods=["GET"])
def api_scan_status():
    with _scan_lock:
        return jsonify(dict(_scan))


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="netinv web UI")
    ap.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8080")))
    a = ap.parse_args()
    print(f"netinv web UI on http://{a.host}:{a.port}  (db: {DB})")
    app.run(host=a.host, port=a.port, threaded=True)
