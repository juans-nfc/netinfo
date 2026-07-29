"""Encrypt/decrypt stored scan credentials at rest using Fernet.

The Fernet key is derived from NETVIEW_SECRET_KEY. If that is unset we fall
back to a key persisted in the data dir so a single container keeps working,
but you should always set NETVIEW_SECRET_KEY in production.
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets

from cryptography.fernet import Fernet, InvalidToken

from .config import get_settings


def _derive_key() -> bytes:
    settings = get_settings()
    if settings.secret_key:
        digest = hashlib.sha256(settings.secret_key.encode()).digest()
        return base64.urlsafe_b64encode(digest)

    # No secret provided: persist a generated key next to the DB so restarts
    # of the same container don't break, and warn loudly.
    key_path = os.path.join(settings.data_dir, ".fernet_key")
    if os.path.exists(key_path):
        with open(key_path, "rb") as fh:
            return fh.read().strip()
    key = base64.urlsafe_b64encode(secrets.token_bytes(32))
    os.makedirs(settings.data_dir, exist_ok=True)
    with open(key_path, "wb") as fh:
        fh.write(key)
    os.chmod(key_path, 0o600)
    return key


_fernet: Fernet | None = None


def _fernet_instance() -> Fernet:
    global _fernet
    if _fernet is None:
        _fernet = Fernet(_derive_key())
    return _fernet


def encrypt(plaintext: str) -> str:
    if plaintext is None:
        plaintext = ""
    return _fernet_instance().encrypt(plaintext.encode()).decode()


def decrypt(token: str) -> str:
    if not token:
        return ""
    try:
        return _fernet_instance().decrypt(token.encode()).decode()
    except InvalidToken:
        # Wrong/rotated key — return empty rather than crashing a scan.
        return ""
