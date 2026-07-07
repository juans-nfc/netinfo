"""
ad.py - enumerate computer objects from Active Directory over LDAP.

In an AD environment this is your authoritative "what should exist" list. You
seed the inventory from AD, then reconcile against what the network scan
actually finds:
  * in AD but never responded  -> offline, stale, or decommissioned object
  * responded but not in AD     -> printer / network gear / IoT / unmanaged host

Uses an NTLM bind (DOMAIN\\user), which needs no extra system libraries.
A read-only account is plenty - reading computer objects is a normal domain
user right; no elevated privilege required just to enumerate.
"""
import datetime as dt
import socket


def _base_dn_from_domain(domain):
    return ",".join(f"DC={p}" for p in domain.split("."))


def _filetime_to_iso(ft):
    """Convert an AD lastLogonTimestamp (100-ns ticks since 1601) to ISO."""
    try:
        ft = int(ft)
    except (TypeError, ValueError):
        return None
    if ft <= 0:
        return None
    # ldap3 sometimes already hands back a datetime; guard for that.
    if isinstance(ft, dt.datetime):
        return ft.isoformat()
    epoch = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
    return (epoch + dt.timedelta(microseconds=ft / 10)).isoformat(timespec="seconds")


def collect_ad_computers(cfg):
    """
    Return (computers, meta) where computers is a list of dicts:
      {hostname, dns, ip, ad_os, ad_last_logon, enabled}
    ip is None when the AD DNS name doesn't resolve (a useful staleness signal).
    """
    from ldap3 import Server, Connection, NTLM, SUBTREE, ALL

    domain = cfg["domain"]
    base_dn = cfg.get("base_dn") or _base_dn_from_domain(domain)
    server = Server(cfg["server"], use_ssl=cfg.get("use_ssl", False), get_info=ALL)
    conn = Connection(
        server,
        user=f"{cfg.get('netbios', domain.split('.')[0]).upper()}\\{cfg['user']}",
        password=cfg["password"],
        authentication=NTLM,
        auto_bind=True,
    )

    attrs = ["dNSHostName", "name", "operatingSystem",
             "lastLogonTimestamp", "userAccountControl"]
    computers, unresolved = [], 0
    conn.search(base_dn, "(objectClass=computer)", search_scope=SUBTREE,
                attributes=attrs, paged_size=500)
    entries = list(conn.entries)
    # follow the paged cookie until AD stops handing out pages
    cookie = conn.result.get("controls", {}).get(
        "1.2.840.113556.1.4.319", {}).get("value", {}).get("cookie")
    while cookie:
        conn.search(base_dn, "(objectClass=computer)", search_scope=SUBTREE,
                    attributes=attrs, paged_size=500, paged_cookie=cookie)
        entries.extend(conn.entries)
        cookie = conn.result.get("controls", {}).get(
            "1.2.840.113556.1.4.319", {}).get("value", {}).get("cookie")

    for e in entries:
        dns_name = str(e.dNSHostName) if e.dNSHostName else None
        name = str(e.name) if e.name else None
        uac = int(e.userAccountControl.value) if e.userAccountControl else 0
        ip = None
        if dns_name:
            try:
                ip = socket.gethostbyname(dns_name)
            except OSError:
                unresolved += 1
        computers.append({
            "hostname": dns_name or name,
            "dns": dns_name,
            "ip": ip,
            "ad_os": str(e.operatingSystem) if e.operatingSystem else None,
            "ad_last_logon": _filetime_to_iso(
                e.lastLogonTimestamp.value if e.lastLogonTimestamp else None),
            "enabled": not bool(uac & 0x2),   # 0x2 = ACCOUNTDISABLE
        })
    conn.unbind()
    meta = {"total": len(computers), "unresolved_dns": unresolved}
    return computers, meta
