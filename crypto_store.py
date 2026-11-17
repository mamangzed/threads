"""Encrypted storage for the Threads automation app.

Security rules:
- Passwords are NEVER stored. Only the Threads session token is stored,
  encrypted with AES-256-GCM under a master key kept in data/master.key (0600).
- The master key is created once on first run and never leaves the server.
"""
import base64
import json
import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def get_or_create_master_key(data_dir: str) -> bytes:
    os.makedirs(data_dir, exist_ok=True)
    path = os.path.join(data_dir, "master.key")
    if os.path.exists(path):
        with open(path, "rb") as f:
            raw = f.read().strip()
        try:
            key = base64.b64decode(raw)
            if len(key) == 32:
                return key
        except Exception:
            pass
        raise RuntimeError("master.key exists but is invalid (expected base64 of 32 bytes)")
    key = secrets.token_bytes(32)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(base64.b64encode(key))
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    os.chmod(path, 0o600)
    return key


def encrypt_token(key: bytes, plaintext: str) -> str:
    aes = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aes.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode("ascii")


def decrypt_token(key: bytes, blob: str) -> str:
    raw = base64.b64decode(blob.encode("ascii"))
    nonce, ct = raw[:12], raw[12:]
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, None).decode("utf-8")


def load_json(path: str, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_json_atomic(path: str, obj) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def append_jsonl(path: str, entry: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def read_jsonl_tail(path: str, limit: int = 200):
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return []
    out = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out
