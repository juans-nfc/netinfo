"""
store.py - SQLite storage for the inventory.

Kept deliberately simple: one wide `devices` row per IP for quick browsing,
plus a `raw_facts` table holding the full JSON blob from each collector so you
never lose data you didn't model yet, plus an `open_ports` table.

Identity note: this starter keys on IP. In a real deployment you'd dedupe on a
stable key (serial number, then MAC) so a device that changes IP stays one
asset. That's the first upgrade I'd make once you see your data.
"""
import json
import sqlite3
import datetime as dt
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    ip           TEXT PRIMARY KEY,
    mac          TEXT,
    hostname     TEXT,
    device_type  TEXT,      -- windows | linux | network | printer | unknown
    vendor       TEXT,
    model        TEXT,
    serial       TEXT,
    os_name      TEXT,
    cpu          TEXT,
    memory_mb    INTEGER,
    source       TEXT,      -- which collector produced the good data
    in_ad        INTEGER DEFAULT 0,   -- 1 = present as an AD computer object
    responded    INTEGER DEFAULT 0,   -- 1 = answered a probe during discovery
    ad_os        TEXT,      -- OS as reported by AD (vs. live-scanned os_name)
    ad_last_logon TEXT,
    first_seen   TEXT,
    last_seen    TEXT
);

CREATE TABLE IF NOT EXISTS raw_facts (
    ip           TEXT,
    collector    TEXT,      -- snmp | ssh | winrm | discovery
    facts_json   TEXT,
    collected_at TEXT
);

CREATE TABLE IF NOT EXISTS open_ports (
    ip     TEXT,
    port   INTEGER,
    proto  TEXT,
    hint   TEXT,
    PRIMARY KEY (ip, port, proto)
);

CREATE TABLE IF NOT EXISTS software (
    ip           TEXT,
    name         TEXT,
    version      TEXT,
    publisher    TEXT,
    install_date TEXT,
    source       TEXT,      -- winrm | ssh
    first_seen   TEXT,      -- when this app first appeared on this host
    last_seen    TEXT,      -- last scan that still saw it (stale = uninstalled)
    PRIMARY KEY (ip, name)
);
CREATE INDEX IF NOT EXISTS idx_software_name ON software(name);
"""


@contextmanager
def connect(path="inventory.db"):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def _now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def upsert_device(conn, ip, **fields):
    """Insert or update a device row. Only non-None fields overwrite existing."""
    now = _now()
    row = conn.execute("SELECT ip FROM devices WHERE ip=?", (ip,)).fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO devices (ip, first_seen, last_seen) VALUES (?,?,?)",
            (ip, now, now),
        )
    cols = {k: v for k, v in fields.items() if v is not None}
    cols["last_seen"] = now
    if cols:
        sets = ", ".join(f"{k}=?" for k in cols)
        conn.execute(f"UPDATE devices SET {sets} WHERE ip=?", (*cols.values(), ip))


def add_raw(conn, ip, collector, facts: dict):
    conn.execute(
        "INSERT INTO raw_facts (ip, collector, facts_json, collected_at) VALUES (?,?,?,?)",
        (ip, collector, json.dumps(facts, default=str), _now()),
    )


def add_port(conn, ip, port, proto, hint=""):
    conn.execute(
        "INSERT OR REPLACE INTO open_ports (ip, port, proto, hint) VALUES (?,?,?,?)",
        (ip, port, proto, hint),
    )


def sync_software(conn, ip, packages, source):
    """Upsert this host's installed software. first_seen is set once and kept;
    last_seen is bumped every scan, so a package whose last_seen falls behind
    the newest scan has been uninstalled since. Returns the scan timestamp."""
    now = _now()
    conn.executemany(
        """INSERT INTO software
             (ip, name, version, publisher, install_date, source, first_seen, last_seen)
           VALUES (?,?,?,?,?,?,?,?)
           ON CONFLICT(ip, name) DO UPDATE SET
             version=excluded.version, publisher=excluded.publisher,
             install_date=excluded.install_date, source=excluded.source,
             last_seen=excluded.last_seen""",
        [(ip, p["name"], p.get("version"), p.get("publisher"),
          p.get("install_date"), source, now, now)
         for p in packages if p.get("name")],
    )
    return now
