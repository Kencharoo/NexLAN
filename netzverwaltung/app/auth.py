"""Anmeldung, Sitzungen, CSRF.

Absichtlich klein gehalten: ein Administratorkonto, Passwort per scrypt
gehasht, Sitzung in einem signierten Cookie. Kein Fremdcode noetig.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time

from fastapi import Request

from . import config
from .store import atomic_write

COOKIE = "nv_session"
SESSION_HOURS = 12
SECRET_FILE = config.ETC / "secret"

# scrypt-Parameter. n=2**15 mit r=8 braucht 128*n*r = genau 32 MiB -- exakt die
# Standardgrenze von OpenSSL, die dabei ueberschritten wird. Deshalb maxmem
# ausdruecklich hochsetzen, sonst schlaegt schon das Setzen des Passworts fehl.
SCRYPT = {"n": 2**15, "r": 8, "p": 1, "dklen": 32, "maxmem": 64 * 1024 * 1024}


def _secret() -> bytes:
    if not SECRET_FILE.exists():
        atomic_write(SECRET_FILE, secrets.token_hex(32), mode=0o600)
    return SECRET_FILE.read_text().strip().encode()


# --- Passwort ---------------------------------------------------------------

def set_password(password: str) -> None:
    if len(password) < 10:
        raise ValueError("Das Passwort muss mindestens 10 Zeichen lang sein.")
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, **SCRYPT)
    atomic_write(config.AUTH_FILE, json.dumps({
        "salt": base64.b64encode(salt).decode(),
        "hash": base64.b64encode(digest).decode(),
    }), mode=0o600)


def check_password(password: str) -> bool:
    if not config.AUTH_FILE.exists():
        return False
    data = json.loads(config.AUTH_FILE.read_text())
    salt = base64.b64decode(data["salt"])
    expected = base64.b64decode(data["hash"])
    digest = hashlib.scrypt(password.encode(), salt=salt, **SCRYPT)
    return hmac.compare_digest(digest, expected)


def password_is_set() -> bool:
    return config.AUTH_FILE.exists()


# --- Sitzung ----------------------------------------------------------------

def issue_session() -> str:
    payload = json.dumps({"exp": int(time.time()) + SESSION_HOURS * 3600,
                          "csrf": secrets.token_urlsafe(16)})
    body = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    sig = hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{body}.{sig}"


def read_session(request: Request) -> dict | None:
    raw = request.cookies.get(COOKIE)
    if not raw or "." not in raw:
        return None
    body, _, sig = raw.rpartition(".")
    expected = hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(sig, expected):
        return None
    padding = "=" * (-len(body) % 4)
    try:
        data = json.loads(base64.urlsafe_b64decode(body + padding))
    except (ValueError, json.JSONDecodeError):
        return None
    if data.get("exp", 0) < time.time():
        return None
    return data


def is_authenticated(request: Request) -> bool:
    return read_session(request) is not None


def csrf_token(request: Request) -> str:
    session = read_session(request)
    return session.get("csrf", "") if session else ""


def csrf_ok(request: Request, submitted: str) -> bool:
    token = csrf_token(request)
    return bool(token) and hmac.compare_digest(token, submitted or "")
