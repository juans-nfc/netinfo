"""MAC address -> hardware vendor lookup.

Uses the mac-vendor-lookup offline database. The OUI file is refreshed at
Docker build time (see Dockerfile) so lookups work with no internet at runtime.
"""
from __future__ import annotations

import logging

log = logging.getLogger("netview.oui")

try:
    from mac_vendor_lookup import MacLookup

    _lookup = MacLookup()
except Exception as exc:  # pragma: no cover
    _lookup = None
    log.warning("mac_vendor_lookup unavailable: %s", exc)


def vendor_for(mac: str | None) -> str | None:
    if not mac or _lookup is None:
        return None
    try:
        return _lookup.lookup(mac)
    except Exception:
        return None
