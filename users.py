"""Multi-user store for the Threads automation app.

Users live in data/users.json (ignored by git, like the rest of data/).
Passwords are stored ONLY as PBKDF2-HMAC-SHA256 hashes (stdlib hashlib).
API keys are stored ONLY as SHA-256 hashes + an 8-char prefix; the plain
key is shown exactly once, at creation/regeneration time.

The "admin" is synthetic: id "admin", email "admin@local", is_admin=True,
no password — admin login happens only through the WEB_PASSWORD gate
(POST /api/login), never through /api/auth/login.
"""
import base64
import hashlib
import re
import secrets
import uuid
from datetime import datetime, timezone

import crypto_store

ADMIN_ID = "admin"
ADMIN_EMAIL = "admin@local"

# Default per-user limits (keputusan Sophie 17 Nov 2026): user biasa
# TANPA BATAS — None berarti unlimited di semua enforcement (cek maks
# akun + cek jatah harian). Alasannya: tiap user bawa proxy sendiri per
# akun, jadi beban IP server tidak lagi jadi alasan pembatasan.
# Struktur limit per-user tetap dipertahankan (untuk paket berbayar
# nanti); admin tetap pakai ADMIN_LIMITS di bawah.
DEFAULT_LIMITS = {"max_accounts": None, "max_posts_per_day": None, "max_replies_per_day": None}
# Admin (gate) limits: generous caps so cron flows never trip them, but
# still finite so the same enforcement code path runs for everyone.
ADMIN_LIMITS = {"max_accounts": 100, "max_posts_per_day": 1000, "max_replies_per_day": 1000}

_PBKDF2_ITERATIONS = 200_000
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _users_file(data_dir):
    import os
    return os.path.join(data_dir, "users.json")


def load_users(data_dir):
    return crypto_store.load_json(_users_file(data_dir), {"users": []})


def save_users(data_dir, doc):
    crypto_store.save_json_atomic(_users_file(data_dir), doc)


def ensure_admin(data_dir):
    """Make sure the synthetic admin record exists; return it."""
    doc = load_users(data_dir)
    admin = next((u for u in doc["users"] if u["id"] == ADMIN_ID), None)
    if admin is None:
        admin = {
            "id": ADMIN_ID,
            "email": ADMIN_EMAIL,
            "password_hash": None,
            "is_admin": True,
            "disabled": False,
            "limits": dict(ADMIN_LIMITS),
            "api_key_hash": None,
            "api_key_prefix": None,
            "api_key_created_at": None,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        doc["users"].append(admin)
        save_users(data_dir, doc)
    return admin


def public_user(u):
    """User record safe to send to a client (no hashes)."""
    if u is None:
        return None
    return {
        "id": u["id"],
        "email": u["email"],
        "is_admin": bool(u.get("is_admin")),
        "limits": dict(u.get("limits") or DEFAULT_LIMITS),
    }


def find_user_by_id(data_dir, user_id):
    if user_id == ADMIN_ID:
        return ensure_admin(data_dir)
    for u in load_users(data_dir)["users"]:
        if u["id"] == user_id:
            return u
    return None


def find_user_by_email(data_dir, email):
    email = (email or "").strip().lower()
    for u in load_users(data_dir)["users"]:
        if (u.get("email") or "").lower() == email:
            return u
    return None


def find_user_by_api_key(data_dir, api_key):
    """Resolve a plain API key to its user (hash comparison only)."""
    if not api_key:
        return None
    digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
    for u in load_users(data_dir)["users"]:
        if u.get("api_key_hash") and secrets.compare_digest(u["api_key_hash"], digest):
            return u
    return None


def hash_password(password):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    return (
        f"pbkdf2_sha256${_PBKDF2_ITERATIONS}$"
        f"{base64.b64encode(salt).decode('ascii')}$"
        f"{base64.b64encode(dk).decode('ascii')}"
    )


def verify_password(password, password_hash):
    if not password_hash or not password:
        return False
    try:
        algo, iters, salt_b64, hash_b64 = password_hash.split("$")
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iters))
        return secrets.compare_digest(dk, expected)
    except Exception:
        return False


def validate_signup(email, password):
    """Return an error string, or None when the input is valid."""
    email = (email or "").strip()
    if not _EMAIL_RE.match(email):
        return "format email tidak valid"
    if not password or len(password) < 8:
        return "password minimal 8 karakter"
    return None


def generate_api_key():
    """Return (plain_key, sha256_hex, prefix). Plain key is shown once."""
    plain = "tk_" + secrets.token_urlsafe(32)
    digest = hashlib.sha256(plain.encode("utf-8")).hexdigest()
    return plain, digest, plain[:8]


def create_user(data_dir, email, password):
    """Create a user; returns (public_user, plain_api_key) or (None, error)."""
    err = validate_signup(email, password)
    if err:
        return None, err
    email = email.strip().lower()
    doc = load_users(data_dir)
    if any((u.get("email") or "").lower() == email for u in doc["users"]):
        return None, "email sudah terdaftar"
    plain, digest, prefix = generate_api_key()
    now = datetime.now(timezone.utc).isoformat()
    user = {
        "id": "u_" + uuid.uuid4().hex[:12],
        "email": email,
        "password_hash": hash_password(password),
        "is_admin": False,
        "disabled": False,
        "limits": dict(DEFAULT_LIMITS),
        "api_key_hash": digest,
        "api_key_prefix": prefix,
        "api_key_created_at": now,
        "created_at": now,
    }
    doc["users"].append(user)
    save_users(data_dir, doc)
    return public_user(user), plain


def regenerate_api_key(data_dir, user_id):
    """Replace the user's API key; returns the plain key (shown once)."""
    doc = load_users(data_dir)
    user = next((u for u in doc["users"] if u["id"] == user_id), None)
    if user is None:
        return None
    plain, digest, prefix = generate_api_key()
    user["api_key_hash"] = digest
    user["api_key_prefix"] = prefix
    user["api_key_created_at"] = datetime.now(timezone.utc).isoformat()
    save_users(data_dir, doc)
    return plain
