"""Security primitives: password hashing, TOTP with replay protection,
field encryption, token generation.

Production notes (see README): the field key would live in a KMS/HSM, the
identity would come from the hospital SSO (OIDC) and MFA from FIDO2 keys.
"""
import hashlib
import hmac
import os
import re
import secrets
import time
from pathlib import Path

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.fernet import Fernet, InvalidToken

from . import db

# argon2id with the library defaults (RFC 9106 low-memory profile)
_ph = PasswordHasher()
_DUMMY_HASH = _ph.hash("timing-equalisation-dummy")

# Injectable clock so tests can step through TOTP windows.
clock = time.time


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    """Always performs one argon2 verification so that unknown users and
    wrong passwords take the same time."""
    try:
        _ph.verify(stored_hash or _DUMMY_HASH, password)
        return stored_hash is not None
    except (VerificationError, InvalidHashError):
        return False


def password_policy_error(password: str) -> str | None:
    if len(password) < 12:
        return "Passwort muss mindestens 12 Zeichen lang sein."
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        return "Passwort braucht Buchstaben und Ziffern."
    return None


# ---------- field encryption (AES-128-CBC + HMAC via Fernet) ----------

def _field_key() -> bytes:
    env = os.environ.get("ZS_KEY")
    if env:
        return env.encode()
    path: Path = db.data_dir() / "field.key"
    if path.exists():
        return path.read_bytes().strip()
    key = Fernet.generate_key()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    return key


def encrypt(text: str) -> str:
    return Fernet(_field_key()).encrypt(text.encode("utf-8")).decode("ascii")


def decrypt(token: str) -> str:
    try:
        return Fernet(_field_key()).decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:  # wrong key or tampered ciphertext
        raise ValueError("Entschluesselung fehlgeschlagen") from exc


# ---------- tokens ----------

def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def safe_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# ---------- TOTP ----------

def new_totp_secret() -> str:
    return pyotp.random_base32()


def verify_totp(secret: str, code: str, last_step: int) -> int | None:
    """Return the accepted time step, or None. A step can only be used once
    (replay protection); +/-1 step tolerance for clock drift."""
    if not re.fullmatch(r"\d{6}", code or ""):
        return None
    totp = pyotp.TOTP(secret)
    current = int(clock() // 30)
    for step in (current - 1, current, current + 1):
        if step > last_step and hmac.compare_digest(totp.generate_otp(step), code):
            return step
    return None


def current_totp(secret: str) -> str:
    return pyotp.TOTP(secret).generate_otp(int(clock() // 30))
