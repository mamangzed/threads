"""Threads automation web app (reverse-engineered API) — HTTP server.

Stdlib ThreadingHTTPServer + one asyncio loop thread (see threads_client).
No build step; frontend is vanilla JS in public/.

Security:
- Web gate: password dari env WEB_PASSWORD. Session cookie, HttpOnly, 24h.
- Instagram passwords are used once at login and never stored. Only the
  Threads session token is stored, AES-256-GCM encrypted (crypto_store).
"""
import hashlib
import hmac
import html
import json
import logging
import mimetypes
import os
import random
import re
import secrets
import threading
import time
import uuid
from datetime import date, datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import crypto_store
import users as users_store
from threads_client import LOOP, ClientRegistry, Need2FA, ThreadsError, _run_caa_register_async, test_proxy_async

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("threads-app")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_DIR = os.path.join(BASE_DIR, "public")
DATA_DIR = os.environ.get("THREADS_DATA_DIR", os.path.join(BASE_DIR, "data"))
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
SESSIONS_DIR = os.path.join(DATA_DIR, "sessions")

WEB_PASSWORD = os.environ.get("WEB_PASSWORD", "")
if not WEB_PASSWORD:
    raise SystemExit("WEB_PASSWORD env wajib diisi (password gate web)")
HOST = "127.0.0.1"
PORT = int(os.environ.get("PORT", "7691"))

ACCOUNTS_FILE = os.path.join(DATA_DIR, "accounts.json")
RULES_FILE = os.path.join(DATA_DIR, "rules.json")
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
ACTIONS_FILE = os.path.join(DATA_DIR, "actions.jsonl")
SEEN_FILE = os.path.join(DATA_DIR, "seen_notifications.json")

DEFAULT_SETTINGS = {
    "max_posts_per_day": 20,
    "max_replies_per_day": 100,
    "max_likes_per_day": 100,
    "min_delay_seconds": 20,
    "auto_reply_enabled": False,
    "auto_comment_enabled": False,
    "max_comments_per_day": 3,
    "comment_min_engagement": 20,
}

PRODUCTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "products.json")
SEEN_COMMENTS_FILE = os.path.join(DATA_DIR, "seen_comments.json")

# Beauty keywords a feed post must contain for an affiliate comment to
# be relevant ("nyambung"). Product keywords are matched against these.
BEAUTY_KEYWORDS = [
    "makeup", "make up", "kosmetik", "kecantikan", "skincare", "skin care",
    "lipstik", "lipstick", "liptint", "lip tint", "lip cream", "lip serum", "bibir",
    "cushion", "foundation", "bedak", "powder", "blush", "eyeshadow", "palette",
    "eyeliner", "maskara", "bulu mata", "serum", "sunscreen", "sun cream",
    "sunblock", "pelembab", "moisturizer", "cream", "toner", "masker", "wajah",
    "parfum", "perfume", "deodoran", "deodorant", "sabun", "shampo", "shampoo",
    "sampo", "hair", "rambut", "catokan", "kuku", "kutek", "kuteks", "nail",
    "henna", "hand cream", "body lotion", "body wash", "lulur", "brush", "kuas",
    "pouch", "tas kosmetik", "alat cukur", "gunting kuku", "glowing", "cantik",
    "makeover", "mua", "beauty",
]

COMMENT_TEMPLATES = [
    "Ngomongin {kw}, aku pakai {product} ini dan cocok banget! Cek di sini ya: {link}",
    "Kalau soal {kw}, coba deh {product}. Bagus lho: {link}",
    "Aku rekomendasiin {product} buat {kw}, harganya {price}. {link}",
    "Ini {product}, aku udah coba dan suka banget. {link}",
    "Buat yang cari {kw}, {product} ini oke banget sih. {link}",
    "Coba {product} deh, {price} aja. Aku belinya di sini: {link}",
]



def _kw_hit(text, keywords):
    """Word-boundary keyword match (so 'mua' does not hit 'semua')."""
    hits = []
    for k in keywords:
        if re.search(r"(?<!\w)" + re.escape(k) + r"(?!\w)", text):
            hits.append(k)
    return hits


def load_products():
    try:
        with open(PRODUCTS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def load_seen_comments():
    try:
        with open(SEEN_COMMENTS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_seen_comments(seen):
    with STORE_LOCK:
        with open(SEEN_COMMENTS_FILE, "w", encoding="utf-8") as f:
            json.dump(seen, f, ensure_ascii=False)

# ------------------------------------------------------------------ state --

MASTER_KEY = None
REGISTRY = None
# cookie token -> {"user_id": ..., "kind": "user"|"admin",
#                  "exp": epoch, "selected_account_id": ...|None}
# kind "admin" = WEB_PASSWORD gate session (user_id "admin").
SESSIONS = {}
SESSIONS_LOCK = threading.Lock()
STORE_LOCK = threading.Lock()


def _key_for_account(acc):
    """Encryption key for one account's token/proxy/session-settings.

    Accounts with enc == "user" use the key derived from the master key
    for their owner; legacy accounts (no owner / undecryptable during
    migration) fall back to the master key directly.
    """
    if MASTER_KEY is None:
        raise RuntimeError("MASTER_KEY belum dimuat")
    if acc.get("enc") == "user" and acc.get("owner_id"):
        return crypto_store.derive_user_key(MASTER_KEY, acc["owner_id"])
    return MASTER_KEY


def _encrypt_for_account(acc, plaintext):
    return crypto_store.encrypt_token(_key_for_account(acc), plaintext)


def _decrypt_for_account(acc, blob):
    return crypto_store.decrypt_token(_key_for_account(acc), blob)

# Feed: NO cache (Sophie's call, 13 Nov 01:29) — the timeline must be
# truly fresh on every load. The Threads timeline API takes ~2.8s per
# call from this VPS and returns only 4 posts per page, so scrolling
# is slower than with a cache, but every page is fetched live and the
# infinite scroll (lazy load via max_id) stays.
def _fetch_feed(account_id, username, max_id):
    """Fetch one timeline page, always live."""
    return REGISTRY.call(
        account_id, username,
        lambda cl: cl.timeline(max_id=max_id), timeout=90,
    )


def _persist_rotated_token(account_id, username):
    """Save a rotated session token if the live one differs from stored.

    Instagram rotates the sessionid via Set-Cookie; the client captures
    it into the live token after every private call (see
    threads_client._sync_rotated_session). Persist the fresh token so
    the next restore uses it instead of the stale one — this is what
    keeps sessions alive instead of dying every day. No-op when
    nothing rotated. Never raises.
    """
    try:
        client = REGISTRY.get(account_id, username)
        token = client.current_token()
        if not token:
            return
        with STORE_LOCK:
            accounts = load_accounts()
            acc = next((a for a in accounts if a["id"] == account_id), None)
            if not acc or not acc.get("token_enc"):
                return
            try:
                stored = _decrypt_for_account(acc, acc["token_enc"])
            except Exception:
                return
            if stored == token:
                return
            acc["token_enc"] = _encrypt_for_account(acc, token)
            save_accounts(accounts)
            log.info("account %s: token sesi diperbarui (rotasi sessionid)", acc.get("username"))
            # Riwayat refresh token (tampil di web): sumber "otomatis".
            # Nilai token/sessionid TIDAK PERNAH ditulis ke log.
            log_action(account_id, acc.get("username") or username, "token_refresh",
                       "otomatis", "ok", "sessionid diperbarui otomatis oleh aplikasi (rotasi dari Instagram)")
    except Exception as e:
        log.warning("persist rotated token gagal: %s", e)


def load_accounts():
    """Load accounts, migrating legacy (pre-multi-user) ones on first sight.

    A legacy account (no owner_id / no enc field) is adopted by the admin
    (owner_id "admin"): its token/proxy/session-settings are decrypted
    with the master key and re-encrypted with the admin's derived key,
    then enc="user" is set and the file saved atomically. An account
    whose secrets cannot be decrypted is NOT fatal: it is marked
    enc="legacy-unreadable", left ownerless, and skipped by later loads
    (endpoints return a clear error if it is ever used).
    """
    accounts = crypto_store.load_json(ACCOUNTS_FILE, [])
    if MASTER_KEY is None or not accounts:
        return accounts
    changed = False
    for acc in accounts:
        if acc.get("enc") == "user" or acc.get("enc") == "legacy-unreadable":
            continue
        owner_id = acc.get("owner_id") or users_store.ADMIN_ID
        try:
            key_old = MASTER_KEY
            key_new = crypto_store.derive_user_key(MASTER_KEY, owner_id)
            for field in ("token_enc", "proxy_enc", "session_settings_enc"):
                blob = acc.get(field)
                if blob:
                    plain = crypto_store.decrypt_token(key_old, blob)
                    acc[field] = crypto_store.encrypt_token(key_new, plain)
            acc["owner_id"] = owner_id
            acc["enc"] = "user"
            changed = True
        except Exception as e:
            log.warning("account %s: migrasi enkripsi gagal, dilewati: %s",
                        acc.get("username"), e)
            acc["enc"] = "legacy-unreadable"
            changed = True
    if changed:
        try:
            save_accounts(accounts)
        except Exception as e:
            log.warning("gagal menyimpan hasil migrasi akun: %s", e)
    return accounts


def save_accounts(accounts):
    crypto_store.save_json_atomic(ACCOUNTS_FILE, accounts)


def load_rules():
    return crypto_store.load_json(RULES_FILE, {})


def save_rules(rules):
    crypto_store.save_json_atomic(RULES_FILE, rules)


def load_settings():
    s = crypto_store.load_json(SETTINGS_FILE, {})
    out = dict(DEFAULT_SETTINGS)
    out.update(s)
    return out


def save_settings(settings):
    crypto_store.save_json_atomic(SETTINGS_FILE, settings)


def load_seen():
    return crypto_store.load_json(SEEN_FILE, {})


def save_seen(seen):
    crypto_store.save_json_atomic(SEEN_FILE, seen)


def get_account(account_id):
    for a in load_accounts():
        if a["id"] == account_id:
            return a
    return None


def get_active_account():
    """Legacy global-active lookup — kept only for display compat.

    Request routing MUST NOT use this anymore; use the per-session
    selected account via Handler._active_client() instead.
    """
    accounts = load_accounts()
    for a in accounts:
        if a.get("active"):
            return a
    return accounts[0] if accounts else None


def _accounts_for_user(user_id, is_admin):
    """Accounts visible to a caller: own accounts, or all for admin."""
    accounts = load_accounts()
    if is_admin:
        return accounts
    return [a for a in accounts if a.get("owner_id") == user_id]


def _owner_email_map():
    """owner_id -> email (admin maps to admin@local)."""
    m = {users_store.ADMIN_ID: users_store.ADMIN_EMAIL}
    try:
        for u in users_store.load_users(DATA_DIR)["users"]:
            m[u["id"]] = u.get("email", "")
    except Exception:
        pass
    return m


def _result_link(res):
    """The public URL of a post/reply just published, if the API
    returned its shortcode (media.code)."""
    if not isinstance(res, dict):
        return None
    media = res.get("media") or res
    code = media.get("code") if isinstance(media, dict) else None
    if code:
        return f"https://www.threads.net/t/{code}"
    return None


def log_action(account_id, username, kind, target, result, detail="", link=None, owner_id=None):
    if owner_id is None:
        # Best-effort: derive the owner from the stored account so
        # per-user daily usage can be counted even for call sites that
        # do not know the caller.
        try:
            for a in load_accounts():
                if a["id"] == account_id and a.get("owner_id"):
                    owner_id = a["owner_id"]
                    break
        except Exception:
            pass
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "account_id": account_id,
        "username": username,
        "type": kind,
        "target": str(target),
        "result": result,
        "detail": detail[:300],
    }
    if owner_id:
        entry["owner_id"] = owner_id
    if link:
        entry["link"] = link
    with STORE_LOCK:
        crypto_store.append_jsonl(ACTIONS_FILE, entry)
    return entry


def count_user_actions_today(user_id, kinds):
    """Successful actions of the given kinds today, across ALL of the
    user's accounts. Counts an entry when its owner_id matches, or —
    for entries written before owner_id existed — when its account_id
    belongs to the user."""
    if isinstance(kinds, str):
        kinds = {kinds}
    else:
        kinds = set(kinds)
    today = date.today().isoformat()
    try:
        owned_ids = {a["id"] for a in load_accounts()
                     if a.get("owner_id") == user_id}
    except Exception:
        owned_ids = set()
    n = 0
    for e in crypto_store.read_jsonl_tail(ACTIONS_FILE, limit=5000):
        if (
            e.get("type") in kinds
            and e.get("result") == "ok"
            and e.get("ts", "")[:10] == today
            and (e.get("owner_id") == user_id or e.get("account_id") in owned_ids)
        ):
            n += 1
    return n


def check_user_daily_limit(user, kind):
    """Per-user daily cap (post / reply), on top of the per-account cap.

    kind "post" counts post+repost entries; kind "reply" counts reply
    entries. Admin limits are generous caps, not a bypass. Returns an
    error string when the cap is hit, else None.
    """
    limits = (user or {}).get("limits") or users_store.DEFAULT_LIMITS
    if kind == "post":
        limit = limits.get("max_posts_per_day", 10)
        used = count_user_actions_today(user["id"], {"post", "repost"})
        label = "post"
    elif kind == "reply":
        limit = limits.get("max_replies_per_day", 20)
        used = count_user_actions_today(user["id"], {"reply"})
        label = "balasan"
    else:
        return None
    if limit is not None and used >= limit:
        return f"Batas harian user tercapai: {label} {used}/{limit} hari ini."
    return None


def user_usage_today(user_id):
    """(accounts, posts_today, replies_today) for admin views."""
    accounts = [a for a in load_accounts() if a.get("owner_id") == user_id]
    return (
        len(accounts),
        count_user_actions_today(user_id, {"post", "repost"}),
        count_user_actions_today(user_id, {"reply"}),
    )


def count_actions_today(account_id, kind):
    today = date.today().isoformat()
    n = 0
    for e in crypto_store.read_jsonl_tail(ACTIONS_FILE, limit=5000):
        if (
            e.get("account_id") == account_id
            and e.get("type") == kind
            and e.get("result") == "ok"
            and e.get("ts", "")[:10] == today
        ):
            n += 1
    return n


def check_daily_limit(account_id, kind, settings):
    limits = {
        "post": settings.get("max_posts_per_day", 20),
        "reply": settings.get("max_replies_per_day", 100),
        "like": settings.get("max_likes_per_day", 100),
    }
    limit = limits.get(kind)
    if limit is None:
        return None
    used = count_actions_today(account_id, kind)
    if used >= limit:
        return f"Batas harian tercapai: {kind} {used}/{limit} hari ini."
    return None


def mask_proxy(proxy):
    """Show only the proxy host (no credentials) for the UI."""
    if not proxy:
        return ""
    try:
        return urlparse(proxy).hostname or ""
    except Exception:
        return ""


def mask_account(a, include_owner=False):
    out = {
        "id": a["id"],
        "username": a["username"],
        "user_id": a.get("user_id"),
        "pic": a.get("pic", ""),
        "active": bool(a.get("active")),
        "status": a.get("status", "unknown"),
        "status_detail": a.get("status_detail", ""),
        "created_at": a.get("created_at"),
        "proxy_set": bool(a.get("proxy_enc")),
        "proxy_host": a.get("proxy_host", ""),
        "owner_id": a.get("owner_id"),
    }
    if include_owner:
        out["owner_email"] = _owner_email_map().get(a.get("owner_id"), "")
    return out


def set_account_status(account_id, status, detail=""):
    with STORE_LOCK:
        accounts = load_accounts()
        for a in accounts:
            if a["id"] == account_id:
                a["status"] = status
                a["status_detail"] = detail
                break
        save_accounts(accounts)


# -------------------------------------------------------------- multipart --

def parse_multipart(body: bytes, content_type: str):
    """Minimal multipart/form-data parser. Returns (fields, files).

    fields: dict name -> str; files: dict name -> (filename, bytes).
    """
    m = re.search(r"boundary=([^;]+)", content_type or "")
    if not m:
        return {}, {}
    boundary = ("--" + m.group(1).strip().strip('"')).encode()
    parts = body.split(boundary)
    fields, files = {}, {}
    for part in parts:
        if not part or part in (b"\r\n", b"--\r\n", b"--"):
            continue
        if b"\r\n\r\n" not in part:
            continue
        head, data = part.split(b"\r\n\r\n", 1)
        if data.endswith(b"\r\n"):
            data = data[:-2]
        if data.endswith(b"--"):
            data = data[:-2]
        hm = re.search(rb'name="([^"]+)"', head)
        if not hm:
            continue
        name = hm.group(1).decode()
        fm = re.search(rb'filename="([^"]*)"', head)
        if fm and fm.group(1):
            files[name] = (fm.group(1).decode(), data)
        else:
            fields[name] = data.decode("utf-8", "replace")
    return fields, files


# ---------------------------------------------------------------- handler --

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # -- plumbing -------------------------------------------------------
    def log_message(self, fmt, *args):  # keep stdout clean-ish
        log.info("%s - %s", self.address_string(), fmt % args)

    def _send_json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, text, status=200, ctype="text/plain; charset=utf-8"):
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path, ctype=None):
        try:
            with open(path, "rb") as f:
                body = f.read()
        except FileNotFoundError:
            return self._send_text("not found", 404)
        ctype = ctype or mimetypes.guess_type(path)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        # Memoized: the body must be drained even when auth fails, or the
        # unread bytes desync the next request on cloudflared's reused
        # keep-alive connection (manifests as a 501 with a garbage method).
        if getattr(self, "_body_cache", None) is None:
            n = int(self.headers.get("Content-Length") or 0)
            self._body_cache = self.rfile.read(n) if n > 0 else b""
        return self._body_cache

    def _read_json(self):
        raw = self._read_body()
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    # -- auth (multi-user) -------------------------------------------
    # self._auth is set by _require_auth(): {"kind": "admin"|"user",
    # "user_id": ..., "user": <user record>, "via": "cookie"|"api_key",
    # "token": <cookie token or None>, "selected_account_id": ...|None}
    _auth = None

    def _session_token(self):
        cookie = self.headers.get("Cookie") or ""
        m = re.search(r"threads_session=([A-Za-z0-9_\-]+)", cookie)
        return m.group(1) if m else None

    def _get_session(self):
        """Valid cookie session dict, or None. Legacy float values
        (pre-multi-user, in-memory only) are upgraded to admin sessions."""
        token = self._session_token()
        if not token:
            return None, None
        with SESSIONS_LOCK:
            sess = SESSIONS.get(token)
        if sess is None:
            return None, None
        if isinstance(sess, (int, float)):  # legacy: bare expiry
            sess = {"user_id": users_store.ADMIN_ID, "kind": "admin",
                    "exp": sess, "selected_account_id": None}
            with SESSIONS_LOCK:
                SESSIONS[token] = sess
        if not isinstance(sess, dict) or sess.get("exp", 0) <= time.time():
            return None, None
        return token, sess

    def _session_valid(self):
        return self._get_session()[1] is not None

    def _resolve_cookie_caller(self):
        token, sess = self._get_session()
        if not sess:
            return None
        user = users_store.find_user_by_id(DATA_DIR, sess["user_id"])
        if user is None or user.get("disabled"):
            return None  # disabled / deleted user: session stops working
        return {"kind": sess.get("kind", "user"), "user_id": user["id"],
                "user": user, "via": "cookie", "token": token,
                "selected_account_id": sess.get("selected_account_id")}

    def _resolve_api_key_caller(self):
        key = (self.headers.get("X-API-Key") or "").strip()
        if not key:
            return None
        user = users_store.find_user_by_api_key(DATA_DIR, key)
        if user is None or user.get("disabled"):
            return None
        return {"kind": "user", "user_id": user["id"], "user": user,
                "via": "api_key", "token": None, "selected_account_id": None}

    def _require_auth(self, allow_api_key=True):
        """Authenticate this request (cookie first, then X-API-Key).

        API keys are NOT valid for /api/auth/* or /api/admin/* — callers
        pass allow_api_key=False for those. Sets self._auth on success.
        """
        self._auth = self._resolve_cookie_caller()
        if self._auth is None and allow_api_key:
            self._auth = self._resolve_api_key_caller()
        if self._auth is None:
            self._send_json({"ok": False, "error": "unauthorized"}, 401)
            return False
        return True

    def _require_admin(self):
        """Cookie admin session only (the WEB_PASSWORD gate)."""
        if not self._require_auth(allow_api_key=False):
            return False
        if self._auth.get("kind") != "admin":
            self._send_json({"ok": False, "error": "hanya admin"}, 403)
            return False
        return True

    def _caller_is_admin(self):
        return bool(self._auth and self._auth.get("kind") == "admin")

    def _caller_user_id(self):
        return self._auth["user_id"] if self._auth else None

    def _owned_account(self, account_id):
        """(account, error) — error is None, "not_found" or "forbidden".

        A foreign account always yields the same generic 403, never a
        hint of whether the id exists.
        """
        acc = get_account(account_id)
        if acc is None:
            return None, "not_found"
        if self._caller_is_admin():
            return acc, None
        if acc.get("owner_id") != self._caller_user_id():
            return None, "forbidden"
        return acc, None

    def _send_account_forbidden(self):
        return self._send_json({"ok": False, "error": "bukan akun Anda"}, 403)

    def _visible_accounts(self):
        return _accounts_for_user(self._caller_user_id(), self._caller_is_admin())

    def _check_account_limit(self, username):
        """403 when the caller already owns max_accounts (unless this is
        a refresh of an account they already own)."""
        if self._caller_is_admin():
            limits = users_store.ADMIN_LIMITS
        else:
            limits = (self._auth["user"] or {}).get("limits") or users_store.DEFAULT_LIMITS
        limit = limits.get("max_accounts", 3)
        owned = self._visible_accounts()
        if username and any(a["username"].lower() == username.lower() for a in owned):
            return False  # refresh of own account: not a new account
        if len(owned) >= limit:
            self._send_json(
                {"ok": False, "error": f"batas akun tercapai (maks {limit})"}, 403)
            return True
        return False

    # -- routing --------------------------------------------------------
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        try:
            if path == "/api/health":
                return self._send_json({"ok": True, "service": "threads-app"})
            if path == "/":
                if self._session_valid():
                    return self._send_file(os.path.join(PUBLIC_DIR, "index.html"), "text/html; charset=utf-8")
                return self._send_file(os.path.join(PUBLIC_DIR, "login.html"), "text/html; charset=utf-8")
            if path.startswith("/static/"):
                name = path[len("/static/"):]
                if ".." in name or name.startswith("/"):
                    return self._send_text("bad path", 400)
                return self._send_file(os.path.join(PUBLIC_DIR, name))
            if not path.startswith("/api/"):
                return self._send_text("not found", 404)
            if path in ("/api/auth/me", "/api/auth/api-key"):
                # cookie login only — API keys never work on /api/auth/*
                if not self._require_auth(allow_api_key=False):
                    return
            elif path.startswith("/api/admin/"):
                if not self._require_admin():
                    return
            elif not self._require_auth():
                return
            return self._route_get(path, qs)
        except BrokenPipeError:
            pass
        except Exception as e:
            log.exception("GET %s failed", path)
            try:
                self._send_json({"ok": False, "error": str(e)[:500]}, 500)
            except Exception:
                pass

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        self._body_cache = None
        try:
            self._read_body()  # drain upfront; a 401 must not leave bytes behind
            if path == "/api/login":
                return self._api_login()
            if path == "/api/auth/signup":
                return self._api_auth_signup()
            if path == "/api/auth/login":
                return self._api_auth_login()
            if path.startswith("/api/admin/"):
                if not self._require_admin():
                    return
            elif path in ("/api/auth/logout", "/api/auth/api-key"):
                # cookie login only — API keys never work on /api/auth/*
                if not self._require_auth(allow_api_key=False):
                    return
            elif not self._require_auth():
                return
            return self._route_post(path)
        except BrokenPipeError:
            pass
        except Exception as e:
            log.exception("POST %s failed", path)
            try:
                self._send_json({"ok": False, "error": str(e)[:500]}, 500)
            except Exception:
                pass

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            if not self._require_auth():
                return
            m = re.match(r"^/api/accounts/([A-Za-z0-9_\-]+)$", path)
            if m:
                return self._api_delete_account(m.group(1))
            m = re.match(r"^/api/rules/([A-Za-z0-9_\-]+)$", path)
            if m:
                return self._api_delete_rule(m.group(1))
            return self._send_json({"ok": False, "error": "not found"}, 404)
        except BrokenPipeError:
            pass
        except Exception as e:
            log.exception("DELETE %s failed", path)
            try:
                self._send_json({"ok": False, "error": str(e)[:500]}, 500)
            except Exception:
                pass

    # -- auth -----------------------------------------------------------
    def _api_login(self):
        body = self._read_json()
        pw = body.get("password", "")
        if hmac.compare_digest(pw, WEB_PASSWORD):
            token = secrets.token_urlsafe(32)
            with SESSIONS_LOCK:
                SESSIONS[token] = {"user_id": users_store.ADMIN_ID, "kind": "admin",
                                   "exp": time.time() + 24 * 3600,
                                   "selected_account_id": None}
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Set-Cookie", f"threads_session={token}; Path=/; HttpOnly; Max-Age=86400")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._send_json({"ok": False, "error": "password salah"}, 401)

    # -- user auth (/api/auth/*) ---------------------------------------
    def _new_session(self, user_id, kind):
        token = secrets.token_urlsafe(32)
        with SESSIONS_LOCK:
            SESSIONS[token] = {"user_id": user_id, "kind": kind,
                               "exp": time.time() + 24 * 3600,
                               "selected_account_id": None}
        return token

    def _send_json_with_cookie(self, obj, token, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Set-Cookie", f"threads_session={token}; Path=/; HttpOnly; Max-Age=86400")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _api_auth_signup(self):
        body = self._read_json()
        email = (body.get("email") or "").strip()
        password = body.get("password") or ""
        pub, res = users_store.create_user(DATA_DIR, email, password)
        if pub is None:
            return self._send_json({"ok": False, "error": res}, 400)
        # res is the plain API key, shown exactly once here.
        return self._send_json({"ok": True, "user": pub, "api_key": res}, 201)

    def _api_auth_login(self):
        body = self._read_json()
        email = (body.get("email") or "").strip()
        password = body.get("password") or ""
        user = users_store.find_user_by_email(DATA_DIR, email)
        if user is None or user.get("is_admin"):
            return self._send_json({"ok": False, "error": "email atau password salah"}, 401)
        if user.get("disabled"):
            return self._send_json({"ok": False, "error": "akun dinonaktifkan"}, 403)
        if not users_store.verify_password(password, user.get("password_hash")):
            return self._send_json({"ok": False, "error": "email atau password salah"}, 401)
        token = self._new_session(user["id"], "user")
        return self._send_json_with_cookie(
            {"ok": True, "user": users_store.public_user(user)}, token)

    def _api_auth_logout(self):
        token = self._session_token()
        if token:
            with SESSIONS_LOCK:
                SESSIONS.pop(token, None)
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Set-Cookie", "threads_session=; Path=/; HttpOnly; Max-Age=0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _api_auth_me(self):
        return self._send_json({"ok": True, "user": users_store.public_user(self._auth["user"])})

    def _api_auth_api_key_get(self):
        user = self._auth["user"]
        if user.get("api_key_hash"):
            return self._send_json({"ok": True, "prefix": user.get("api_key_prefix"),
                                    "created_at": user.get("api_key_created_at")})
        return self._send_json({"ok": True, "api_key": None})

    def _api_auth_api_key_regen(self):
        plain = users_store.regenerate_api_key(DATA_DIR, self._auth["user_id"])
        if plain is None:
            return self._send_json({"ok": False, "error": "user tidak ditemukan"}, 404)
        return self._send_json({"ok": True, "api_key": plain})

    # -- admin (/api/admin/*, kind "admin" only) -----------------------
    def _api_admin_users(self):
        out = []
        for u in users_store.load_users(DATA_DIR)["users"]:
            n_acc, n_post, n_reply = user_usage_today(u["id"])
            out.append({**users_store.public_user(u),
                        "disabled": bool(u.get("disabled")),
                        "accounts": n_acc,
                        "posts_today": n_post,
                        "replies_today": n_reply,
                        "created_at": u.get("created_at"),
                        "api_key_prefix": u.get("api_key_prefix")})
        return self._send_json({"ok": True, "users": out})

    def _api_admin_usage(self):
        out = []
        for u in users_store.load_users(DATA_DIR)["users"]:
            n_acc, n_post, n_reply = user_usage_today(u["id"])
            out.append({"id": u["id"], "email": u["email"],
                        "is_admin": bool(u.get("is_admin")),
                        "disabled": bool(u.get("disabled")),
                        "accounts": n_acc, "posts_today": n_post,
                        "replies_today": n_reply,
                        "limits": dict(u.get("limits") or users_store.DEFAULT_LIMITS)})
        return self._send_json({"ok": True, "usage": out})

    def _api_admin_set_disabled(self, user_id, disabled):
        if user_id == users_store.ADMIN_ID:
            return self._send_json({"ok": False, "error": "admin tidak bisa dinonaktifkan"}, 400)
        doc = users_store.load_users(DATA_DIR)
        user = next((u for u in doc["users"] if u["id"] == user_id), None)
        if user is None:
            return self._send_json({"ok": False, "error": "user tidak ditemukan"}, 404)
        user["disabled"] = disabled
        users_store.save_users(DATA_DIR, doc)
        if disabled:
            # Invalidate any live sessions of this user at once.
            with SESSIONS_LOCK:
                for tok in [t for t, s in SESSIONS.items()
                            if isinstance(s, dict) and s.get("user_id") == user_id]:
                    SESSIONS.pop(tok, None)
        return self._send_json({"ok": True, "user": users_store.public_user(user),
                                "disabled": disabled})

    def _api_admin_set_limits(self, user_id):
        body = self._read_json()
        doc = users_store.load_users(DATA_DIR)
        user = next((u for u in doc["users"] if u["id"] == user_id), None)
        if user is None:
            return self._send_json({"ok": False, "error": "user tidak ditemukan"}, 404)
        limits = dict(user.get("limits") or users_store.DEFAULT_LIMITS)
        for key in ("max_accounts", "max_posts_per_day", "max_replies_per_day"):
            if key in body:
                try:
                    v = int(body[key])
                except (TypeError, ValueError):
                    return self._send_json({"ok": False, "error": f"{key} harus angka"}, 400)
                if v < 0:
                    return self._send_json({"ok": False, "error": f"{key} tidak boleh negatif"}, 400)
                limits[key] = v
        user["limits"] = limits
        users_store.save_users(DATA_DIR, doc)
        return self._send_json({"ok": True, "user": users_store.public_user(user)})

    # -- GET routes ------------------------------------------------------
    def _route_get(self, path, qs):
        if path == "/api/auth/me":
            return self._api_auth_me()
        if path == "/api/auth/api-key":
            return self._api_auth_api_key_get()
        if path == "/api/admin/users":
            return self._api_admin_users()
        if path == "/api/admin/usage":
            return self._api_admin_usage()
        if path == "/api/accounts":
            accounts = [mask_account(a, include_owner=self._caller_is_admin())
                        for a in self._visible_accounts()]
            return self._send_json({"ok": True, "accounts": accounts})
        if path == "/api/settings":
            return self._send_json({"ok": True, "settings": load_settings(),
                                    "products": len(load_products())})
        if path == "/api/rules":
            account, _, err = self._active_client()
            if err:
                return self._send_json({"ok": False, "error": err}, 400)
            rules = load_rules().get(account["id"], [])
            return self._send_json({"ok": True, "account": mask_account(account), "rules": rules})
        if path == "/api/history":
            limit = int((qs.get("limit") or ["200"])[0])
            items = crypto_store.read_jsonl_tail(ACTIONS_FILE, limit=limit)
            if not self._caller_is_admin():
                owned_ids = {a["id"] for a in self._visible_accounts()}
                uid = self._caller_user_id()
                items = [e for e in items
                         if e.get("owner_id") == uid or e.get("account_id") in owned_ids]
            items.reverse()
            return self._send_json({"ok": True, "items": items})
        if path == "/api/token-refreshes":
            # Riwayat pergantian token sesi (rotasi otomatis aplikasi +
            # sinkronisasi extension Chrome + tempel manual). Nilai token /
            # sessionid tidak pernah disimpan di log ini.
            raw = crypto_store.read_jsonl_tail(ACTIONS_FILE, limit=2000)
            items = [e for e in raw if e.get("type") == "token_refresh"]
            if not self._caller_is_admin():
                owned_ids = {a["id"] for a in self._visible_accounts()}
                uid = self._caller_user_id()
                items = [e for e in items
                         if e.get("owner_id") == uid or e.get("account_id") in owned_ids]
            items.reverse()  # terbaru dulu
            summary = {}
            for e in items:
                u = e.get("username") or "?"
                ssum = summary.setdefault(u, {"username": u, "count": 0, "last_ts": None, "last_source": None})
                ssum["count"] += 1
                if not ssum["last_ts"]:
                    ssum["last_ts"] = e.get("ts")
                    ssum["last_source"] = e.get("target")
            return self._send_json({"ok": True, "items": items[:100],
                                    "summary": sorted(summary.values(), key=lambda x: x["username"])})
        if path == "/api/feed/search":
            return self._api_feed_search(qs)
        m = re.match(r"^/api/profile/([A-Za-z0-9_\-]+)$", path)
        if m:
            return self._api_profile(m.group(1), qs)
        if path == "/api/feed":
            return self._api_feed(qs)
        if path == "/api/inbox":
            return self._api_inbox(qs)
        m = re.match(r"^/api/post/([A-Za-z0-9_\-]+)$", path)
        if m:
            return self._api_post_detail(m.group(1))
        if path == "/api/search-user":
            q = (qs.get("q") or [""])[0]
            return self._api_search_user(q)
        return self._send_json({"ok": False, "error": "not found"}, 404)

    def _active_client(self):
        """The caller's selected account: the account chosen in THIS
        session (POST /api/accounts/{id}/select), falling back to the
        caller's first owned account. The global `active` flag in
        accounts.json is never read for routing anymore (it is still
        written, for display compat)."""
        visible = self._visible_accounts()
        if not visible:
            return None, None, "belum ada akun — tambah akun dulu"
        selected = (self._auth or {}).get("selected_account_id")
        account = next((a for a in visible if a["id"] == selected), None)
        if account is None and (self._auth or {}).get("via") == "api_key":
            # API-key callers have no session to hold a selection, so
            # their select (which also flips the global flag) is honoured
            # here. Cookie sessions never read the global flag.
            account = next((a for a in visible if a.get("active")), None)
        if account is None:
            account = visible[0]
        if account.get("enc") == "legacy-unreadable":
            return None, None, "akun tidak bisa dipakai: token lama tidak bisa didekripsi"
        return account, REGISTRY.get(account["id"], account["username"]), None

    def _api_feed(self, qs):
        account, _, err = self._active_client()
        if err:
            return self._send_json({"ok": False, "error": err}, 400)
        max_id = (qs.get("max_id") or [None])[0]
        try:
            res = _fetch_feed(account["id"], account["username"], max_id)
        except ThreadsError as e:
            set_account_status(account["id"], "error", str(e))
            log_action(account["id"], account["username"], "feed", "", "error", str(e))
            return self._send_json({"ok": False, "error": str(e)}, 400)
        _persist_rotated_token(account["id"], account["username"])
        return self._send_json({"ok": True, "account": mask_account(account), **res})

    def _api_feed_search(self, qs):
        account, _, err = self._active_client()
        if err:
            return self._send_json({"ok": False, "error": err}, 400)
        q = (qs.get("q") or [""])[0].strip()
        if not q:
            return self._send_json({"ok": True, "items": []})
        needle = q.lower()
        found = []
        seen = set()
        max_id = None
        # Page through the timeline (max 3 pages) and keep posts whose
        # text / username / full name contain the keyword. Every page
        # is fetched live (no cache). Note: this only searches the
        # home timeline, not all of Threads — there is no public
        # global keyword-search endpoint in the private API.
        for _ in range(3):
            try:
                res = _fetch_feed(account["id"], account["username"], max_id)
            except ThreadsError as e:
                if not found:
                    return self._send_json({"ok": False, "error": str(e)}, 400)
                break
            for p in res.get("items") or []:
                pid = p.get("id")
                if not pid or pid in seen:
                    continue
                seen.add(pid)
                a = p.get("author") or {}
                hay = " ".join([p.get("text") or "", a.get("username") or "", a.get("full_name") or ""]).lower()
                if needle in hay:
                    found.append(p)
            max_id = res.get("next_max_id")
            if not res.get("more_available") or not max_id:
                break
        return self._send_json({"ok": True, "items": found})

    def _api_profile(self, user_id, qs):
        account, _, err = self._active_client()
        if err:
            return self._send_json({"ok": False, "error": err}, 400)
        tab = (qs.get("tab") or ["posts"])[0]
        max_id = (qs.get("max_id") or [None])[0]
        try:
            if tab == "replies":
                res = REGISTRY.call(
                    account["id"], account["username"],
                    lambda cl: cl.user_replies(user_id, max_id=max_id), timeout=90,
                )
            else:
                res = REGISTRY.call(
                    account["id"], account["username"],
                    lambda cl: cl.user_threads(user_id, max_id=max_id), timeout=90,
                )
        except ThreadsError as e:
            return self._send_json({"ok": False, "error": str(e)}, 400)
        return self._send_json({"ok": True, **res})

    def _api_post_detail(self, post_id):
        account, _, err = self._active_client()
        if err:
            return self._send_json({"ok": False, "error": err}, 400)
        try:
            res = REGISTRY.call(
                account["id"], account["username"],
                lambda cl: cl.get_post_detail(post_id), timeout=90,
            )
        except ThreadsError as e:
            return self._send_json({"ok": False, "error": str(e)}, 400)
        return self._send_json({"ok": True, "account": mask_account(account), **res})

    def _api_search_user(self, q):
        account, _, err = self._active_client()
        if err:
            return self._send_json({"ok": False, "error": err}, 400)
        if not q:
            return self._send_json({"ok": True, "users": []})
        try:
            res = REGISTRY.call(
                account["id"], account["username"],
                lambda cl: cl.search_user(q), timeout=60,
            )
        except ThreadsError as e:
            return self._send_json({"ok": False, "error": str(e)}, 400)
        return self._send_json({"ok": True, **res})

    def _api_inbox(self, qs):
        account, _, err = self._active_client()
        if err:
            return self._send_json({"ok": False, "error": err}, 400)
        max_id = (qs.get("max_id") or [None])[0]
        try:
            res = REGISTRY.call(
                account["id"], account["username"],
                lambda cl: cl.notifications(max_id=max_id), timeout=90,
            )
        except ThreadsError as e:
            return self._send_json({"ok": False, "error": str(e)}, 400)
        items = res.get("items", [])[:10]
        seen = load_seen().get(account["id"], {})
        # enrich each item with its parent post (what was commented on)
        for it in items:
            it["handled"] = seen.get(it["id"], "")
            if it.get("post_id"):
                try:
                    parent = REGISTRY.call(
                        account["id"], account["username"],
                        lambda cl, pid=it["post_id"]: cl.get_post_detail(pid), timeout=60,
                    )
                    p = parent.get("post") or {}
                    it["parent"] = {
                        "author": (p.get("author") or {}).get("username", ""),
                        "text": p.get("text", ""),
                        "image_url": p.get("image_url"),
                    }
                except Exception as e:
                    it["parent"] = {"author": "", "text": "", "error": str(e)[:200]}
        return self._send_json(
            {"ok": True, "account": mask_account(account), "items": items,
             "next_max_id": res.get("next_max_id")}
        )

    # -- POST routes -----------------------------------------------------
    def _route_post(self, path):
        if path == "/api/auth/logout":
            return self._api_auth_logout()
        if path == "/api/auth/api-key":
            return self._api_auth_api_key_regen()
        m = re.match(r"^/api/admin/users/([A-Za-z0-9_\-]+)/disable$", path)
        if m:
            return self._api_admin_set_disabled(m.group(1), True)
        m = re.match(r"^/api/admin/users/([A-Za-z0-9_\-]+)/enable$", path)
        if m:
            return self._api_admin_set_disabled(m.group(1), False)
        m = re.match(r"^/api/admin/users/([A-Za-z0-9_\-]+)/limits$", path)
        if m:
            return self._api_admin_set_limits(m.group(1))
        if path == "/api/accounts":
            return self._api_add_account()
        if path == "/api/test-proxy":
            return self._api_test_proxy()
        if path == "/api/register/start":
            return self._api_register_start()
        if path == "/api/register/confirm":
            return self._api_register_confirm()
        if path == "/api/register/resend":
            return self._api_register_resend()
        if path == "/api/settings":
            return self._api_save_settings()
        if path == "/api/rules":
            return self._api_add_rule()
        if path == "/api/posts":
            return self._api_publish()
        m = re.match(r"^/api/accounts/([A-Za-z0-9_\-]+)/select$", path)
        if m:
            return self._api_select_account(m.group(1))
        m = re.match(r"^/api/accounts/([A-Za-z0-9_\-]+)/pic$", path)
        if m:
            return self._api_account_pic(m.group(1))
        m = re.match(r"^/api/accounts/([A-Za-z0-9_\-]+)/proxy$", path)
        if m:
            return self._api_set_account_proxy(m.group(1))
        m = re.match(r"^/api/posts/([A-Za-z0-9_\-]+)/(like|unlike|repost|reply|delete)$", path)
        if m:
            return self._api_post_action(m.group(1), m.group(2))
        m = re.match(r"^/api/users/([A-Za-z0-9_\-]+)/(follow|unfollow)$", path)
        if m:
            return self._api_user_action(m.group(1), m.group(2))
        m = re.match(r"^/api/inbox/([^/]+)/(reply|like|ignore)$", path)
        if m:
            return self._api_inbox_action(m.group(1), m.group(2))
        m = re.match(r"^/api/rules/([A-Za-z0-9_\-]+)/toggle$", path)
        if m:
            return self._api_toggle_rule(m.group(1))
        return self._send_json({"ok": False, "error": "not found"}, 404)

    def _api_add_account(self):
        body = self._read_json()
        # Sumber pergantian token: "extension" bila dikirim extension
        # Chrome, selain itu "manual" (tempel sessionid / login password).
        refresh_source = "extension" if (body.get("source") or "").strip().lower() == "extension" else "manual"
        sessionid = (body.get("sessionid") or "").strip() or None
        username = (body.get("username") or "").strip().lstrip("@")
        password = (body.get("password") or "")
        code = (body.get("code") or "").strip() or None
        totp_key = (body.get("totp_key") or "").strip() or None
        proxy = (body.get("proxy") or "").strip() or None
        # Resolve the username from the caller's own stored account first
        # (sessionid prefix is the platform user id), so a refresh via
        # sessionid is recognised as such by the account-cap check below.
        if sessionid and not username:
            m_uid = re.match(r"^(\d+)", sessionid or "")
            if m_uid:
                uid = m_uid.group(1)
                for a in self._visible_accounts():
                    if str(a.get("user_id") or "") == uid and a.get("username"):
                        username = a["username"]
                        break
        # Per-user account cap (refresh of an account the caller already
        # owns does not count as a new account).
        if self._check_account_limit(username):
            return
        # A username owned by ANOTHER user can never be added here — the
        # owner check below treats it as foreign (403), it is not a
        # refresh.
        if username and not self._caller_is_admin():
            foreign = next((a for a in load_accounts()
                            if a["username"].lower() == username.lower()
                            and a.get("owner_id") not in (None, "", self._caller_user_id())), None)
            if foreign:
                return self._send_account_forbidden()
        if sessionid:
            # Login via a session captured in the user's own browser.
            # The password-login endpoint is rate-limited (429) from this
            # server's IP, while authenticated calls work fine.
            if proxy:
                # Verify the proxy actually works before using it — a
                # dead proxy would make the feed check fail with a
                # misleading "sesi tidak valid" error.
                try:
                    res = LOOP.run(lambda: test_proxy_async(proxy), timeout=60)
                except Exception as e:
                    return self._send_json({"ok": False, "error": f"Proxy tidak bisa diverifikasi: {str(e)[:200]}"}, 400)
                if not res.get("ok"):
                    return self._send_json({"ok": False, "error": res.get("detail") or "Proxy tidak aktif."}, 400)
            # Resolve username from the stored account (by user_id in the
            # sessionid) so a Threads-web sessionid — whose IG user_info
            # call can fail — still maps to the right account instead of
            # erroring "username tidak terbaca".
            if not username:
                m_uid = re.match(r"^(\d+)", sessionid or "")
                if m_uid:
                    uid = m_uid.group(1)
                    for a in self._visible_accounts():
                        if str(a.get("user_id") or "") == uid and a.get("username"):
                            username = a["username"]
                            break
            account_id = uuid.uuid4().hex[:12]
            client = REGISTRY.get(account_id, "")
            try:
                token, user_id = LOOP.run(
                    lambda: client.login_by_sessionid(sessionid, username or None, proxy=proxy), timeout=120
                )
            except ThreadsError as e:
                REGISTRY.drop(account_id)
                log_action(account_id, "", "login", "", "error", str(e))
                return self._send_json({"ok": False, "error": str(e)}, 400)
            except Exception as e:
                REGISTRY.drop(account_id)
                log_action(account_id, "", "login", "", "error", str(e))
                return self._send_json({"ok": False, "error": str(e)[:500]}, 400)
            username = client.username or ""
            if not username:
                REGISTRY.drop(account_id)
                return self._send_json({"ok": False, "error": "Login sesi berhasil tapi username tidak terbaca."}, 400)
        else:
            if not username or not password:
                return self._send_json({"ok": False, "error": "username dan password wajib diisi"}, 400)
            accounts = self._visible_accounts()
            existing = next((a for a in accounts if a["username"].lower() == username.lower()), None)
            account_id = existing["id"] if existing else uuid.uuid4().hex[:12]
            client = REGISTRY.get(account_id, username)
            try:
                token, user_id = LOOP.run(
                    lambda: client.login(username, password, code, totp_key=totp_key, proxy=proxy), timeout=180
                )
            except Need2FA as e:
                log_action(account_id, username, "login", "", "need_2fa", str(e))
                return self._send_json({"ok": False, "need_2fa": True, "error": str(e)}, 401)
            except ThreadsError as e:
                log_action(account_id, username, "login", "", "error", str(e))
                return self._send_json({"ok": False, "error": str(e)}, 400)
            except Exception as e:
                log_action(account_id, username, "login", "", "error", str(e))
                return self._send_json({"ok": False, "error": str(e)[:500]}, 400)
        # Secrets are encrypted with the OWNER's derived key, never the
        # raw master key (see _key_for_account / derive_user_key).
        ukey = crypto_store.derive_user_key(MASTER_KEY, self._caller_user_id())
        enc = crypto_store.encrypt_token(ukey, token)
        # A CAA-created session must be restored under the exact device
        # identity it was created with — persist it (encrypted, like the
        # token) so restores after a restart keep the same identity.
        session_settings_enc = None
        session_settings = getattr(client, "_session_settings", None)
        if session_settings:
            try:
                session_settings_enc = crypto_store.encrypt_token(
                    ukey, json.dumps(session_settings)
                )
            except Exception as e:
                log.warning("gagal enkripsi session settings: %s", e)
        # The proxy (if given) is stored encrypted like the token and
        # used for all of this account's traffic from now on — not just
        # this login. The host alone is kept in plain text for the UI.
        proxy_enc = None
        proxy_host = ""
        if proxy:
            try:
                proxy_enc = crypto_store.encrypt_token(ukey, proxy)
                proxy_host = mask_proxy(proxy)
            except Exception as e:
                log.warning("gagal enkripsi proxy: %s", e)
        # Token lama (bila akun sudah ada) — dipakai sesudah simpan untuk
        # membedakan "login pertama" dari "refresh token" (ganti sessionid).
        _prev = next((a for a in self._visible_accounts() if a["username"].lower() == username.lower()), None)
        prev_token_enc = _prev.get("token_enc") if _prev else None
        now = datetime.now(timezone.utc).isoformat()
        owner_id = self._caller_user_id()
        with STORE_LOCK:
            accounts = load_accounts()
            existing = next((a for a in accounts
                             if a["username"].lower() == username.lower()
                             and (self._caller_is_admin() or a.get("owner_id") == owner_id)), None)
            if existing:
                upd = {"token_enc": enc, "user_id": str(user_id), "status": "ok", "status_detail": "",
                       "owner_id": existing.get("owner_id") or owner_id, "enc": "user"}
                if session_settings_enc:
                    upd["session_settings_enc"] = session_settings_enc
                if proxy_enc:
                    upd["proxy_enc"] = proxy_enc
                    upd["proxy_host"] = proxy_host
                existing.update(upd)
                account_id = existing["id"]
            else:
                new_acc = {
                    "id": account_id, "username": username, "user_id": str(user_id),
                    "token_enc": enc, "owner_id": owner_id, "enc": "user",
                    "active": not any(a.get("owner_id") == owner_id for a in accounts),
                    "status": "ok", "status_detail": "", "created_at": now,
                }
                if session_settings_enc:
                    new_acc["session_settings_enc"] = session_settings_enc
                if proxy_enc:
                    new_acc["proxy_enc"] = proxy_enc
                    new_acc["proxy_host"] = proxy_host
                accounts.append(new_acc)
            save_accounts(accounts)
        if sessionid and account_id != client.account_id:
            # Session login used a temp registry id; move the live client
            # under the stored account id.
            REGISTRY.drop(client.account_id)
            live = REGISTRY.get(account_id, username)
            try:
                LOOP.run(lambda: live.restore(token, str(user_id), username, proxy=proxy), timeout=60)
            except Exception as e:
                log_action(account_id, username, "login", "", "error", f"restore setelah login sesi gagal: {e}")
        # Akun lama yang tokennya berubah = refresh token (bukan login
        # pertama): catat sumbernya (extension / manual) ke riwayat.
        if prev_token_enc and prev_token_enc != enc:
            detail = ("sessionid baru disinkronkan dari extension Chrome"
                      if refresh_source == "extension"
                      else "sessionid baru ditempel manual / login ulang")
            log_action(account_id, username, "token_refresh", refresh_source, "ok", detail)
        log_action(account_id, username, "login", "", "ok", "login berhasil, token tersimpan terenkripsi")
        return self._send_json({"ok": True, "account": mask_account(get_account(account_id))})

    def _api_test_proxy(self):
        body = self._read_json()
        proxy = (body.get("proxy") or "").strip() or None
        if not proxy:
            return self._send_json({"ok": False, "detail": "Proxy kosong — isi dulu kolom Proxy."}, 400)
        try:
            res = LOOP.run(lambda: test_proxy_async(proxy), timeout=60)
        except Exception as e:
            return self._send_json({"ok": False, "detail": f"Gagal: {str(e)[:200]}"}, 400)
        return self._send_json(res)

    # -- Registrasi akun baru (CAA direct-API, tanpa browser) --------------
    def _api_register_start(self):
        """Fase 1: form pendaftaran -> helper CAA jalankan alur sampai kode
        OTP dikirim -> UI menampilkan kolom kode. Password & proxy hanya
        transit (tidak disimpan); state CAA disimpan helper di disk."""
        body = self._read_json()
        phone = (body.get("phone") or "").strip()
        email = (body.get("email") or "").strip()
        contact_type = (body.get("contact_type") or "").strip().lower()
        if not contact_type:
            contact_type = "email" if email else "phone"
        contact = email if contact_type == "email" else phone
        username = (body.get("username") or "").strip().lstrip("@")
        password = body.get("password") or ""
        full_name = (body.get("full_name") or "").strip()
        proxy = (body.get("proxy") or "").strip() or None
        if not contact or not username or not password:
            return self._send_json({"ok": False, "error": "Nomor HP / email, username, dan password wajib diisi."}, 400)
        if proxy:
            try:
                res = LOOP.run(lambda: test_proxy_async(proxy), timeout=60)
            except Exception as e:
                return self._send_json({"ok": False, "error": f"Proxy tidak bisa diverifikasi: {str(e)[:200]}"}, 400)
            if not res.get("ok"):
                return self._send_json({"ok": False, "error": res.get("detail") or "Proxy tidak aktif."}, 400)
        try:
            day = int(body.get("day")); month = int(body.get("month")); year = int(body.get("year"))
        except Exception:
            return self._send_json({"ok": False, "error": "Tanggal lahir tidak valid."}, 400)
        payload = {"phase": "start", "username": username, "password": password,
                   "contact_type": contact_type, "contact": contact,
                   "phone": phone, "email": email, "full_name": full_name, "day": day, "month": month,
                   "year": year, "proxy": proxy or "",
                   "state_dir": os.path.join(DATA_DIR, "reg_pending")}
        try:
            res = LOOP.run(lambda: _run_caa_register_async(payload), timeout=250)
        except Exception as e:
            return self._send_json({"ok": False, "error": str(e)[:300]}, 400)
        if not res.get("ok"):
            return self._send_json(res, 400)
        return self._send_json(res)

    def _api_register_confirm(self):
        """Fase 2: kode OTP (+ password & proxy dari form) -> helper selesaikan
        pendaftaran -> akun baru langsung masuk daftar, seperti login sessionid
        (jalur yang terbukti: token + settings terenkripsi, proxy terenkripsi)."""
        body = self._read_json()
        username = (body.get("username") or "").strip().lstrip("@")
        code = (body.get("code") or "").strip()
        password = body.get("password") or ""
        proxy = (body.get("proxy") or "").strip() or None
        if not username or not code or not password:
            return self._send_json({"ok": False, "error": "Username, kode OTP, dan password wajib diisi."}, 400)
        if self._check_account_limit(username):
            return
        payload = {"phase": "confirm", "username": username, "code": code,
                   "password": password, "proxy": proxy or "",
                   "state_dir": os.path.join(DATA_DIR, "reg_pending")}
        try:
            res = LOOP.run(lambda: _run_caa_register_async(payload), timeout=250)
        except Exception as e:
            return self._send_json({"ok": False, "error": str(e)[:300]}, 400)
        if not res.get("ok"):
            return self._send_json(res, 400)
        sessionid = res.get("sessionid")
        settings = res.get("settings") or {}
        if not sessionid:
            return self._send_json({"ok": False, "error": "Pendaftaran selesai tapi sessionid tidak didapat."}, 400)
        if proxy:
            try:
                pres = LOOP.run(lambda: test_proxy_async(proxy), timeout=60)
            except Exception as e:
                return self._send_json({"ok": False, "error": f"Proxy tidak bisa diverifikasi: {str(e)[:200]}"}, 400)
            if not pres.get("ok"):
                return self._send_json({"ok": False, "error": pres.get("detail") or "Proxy tidak aktif."}, 400)
        if self._check_account_limit(username):
            return
        if username and not self._caller_is_admin():
            foreign = next((a for a in load_accounts()
                            if a["username"].lower() == username.lower()
                            and a.get("owner_id") not in (None, "", self._caller_user_id())), None)
            if foreign:
                return self._send_account_forbidden()
        accounts = self._visible_accounts()
        existing = next((a for a in accounts if a["username"].lower() == username.lower()), None)
        account_id = existing["id"] if existing else uuid.uuid4().hex[:12]
        client = REGISTRY.get(account_id, username)
        try:
            token, user_id = LOOP.run(
                lambda: client.login_by_sessionid(sessionid, username or None, settings=settings, proxy=proxy), timeout=120
            )
        except ThreadsError as e:
            REGISTRY.drop(account_id)
            log_action(account_id, username, "login", "", "error", str(e))
            return self._send_json({"ok": False, "error": f"Akun dibuat tapi gagal masuk: {e}"}, 400)
        except Exception as e:
            REGISTRY.drop(account_id)
            log_action(account_id, username, "login", "", "error", str(e))
            return self._send_json({"ok": False, "error": f"Akun dibuat tapi gagal masuk: {str(e)[:300]}"}, 400)
        username = client.username or ""
        if not username:
            REGISTRY.drop(account_id)
            return self._send_json({"ok": False, "error": "Akun dibuat tapi username tidak terbaca."}, 400)
        ukey = crypto_store.derive_user_key(MASTER_KEY, self._caller_user_id())
        enc = crypto_store.encrypt_token(ukey, token)
        session_settings_enc = None
        session_settings = getattr(client, "_session_settings", None)
        if session_settings:
            try:
                session_settings_enc = crypto_store.encrypt_token(
                    ukey, json.dumps(session_settings)
                )
            except Exception as e:
                log.warning("gagal enkripsi session settings: %s", e)
        proxy_enc = None
        proxy_host = ""
        if proxy:
            try:
                proxy_enc = crypto_store.encrypt_token(ukey, proxy)
                proxy_host = mask_proxy(proxy)
            except Exception as e:
                log.warning("gagal enkripsi proxy: %s", e)
        now = datetime.now(timezone.utc).isoformat()
        owner_id = self._caller_user_id()
        with STORE_LOCK:
            accounts = load_accounts()
            existing = next((a for a in accounts
                             if a["username"].lower() == username.lower()
                             and (self._caller_is_admin() or a.get("owner_id") == owner_id)), None)
            if existing:
                upd = {"token_enc": enc, "user_id": str(user_id), "status": "ok", "status_detail": "",
                       "owner_id": existing.get("owner_id") or owner_id, "enc": "user"}
                if session_settings_enc:
                    upd["session_settings_enc"] = session_settings_enc
                if proxy_enc:
                    upd["proxy_enc"] = proxy_enc
                    upd["proxy_host"] = proxy_host
                existing.update(upd)
                account_id = existing["id"]
            else:
                new_acc = {
                    "id": account_id, "username": username, "user_id": str(user_id),
                    "token_enc": enc, "owner_id": owner_id, "enc": "user",
                    "active": not any(a.get("owner_id") == owner_id for a in accounts),
                    "status": "ok", "status_detail": "", "created_at": now,
                }
                if session_settings_enc:
                    new_acc["session_settings_enc"] = session_settings_enc
                if proxy_enc:
                    new_acc["proxy_enc"] = proxy_enc
                    new_acc["proxy_host"] = proxy_host
                accounts.append(new_acc)
            save_accounts(accounts)
        log_action(account_id, username, "login", "", "ok", "akun baru terdaftar via CAA, token tersimpan terenkripsi")
        return self._send_json({"ok": True, "account": mask_account(get_account(account_id))})

    def _api_register_resend(self):
        """Kirim ulang kode OTP untuk pendaftaran yang sedang berjalan."""
        body = self._read_json()
        username = (body.get("username") or "").strip().lstrip("@")
        proxy = (body.get("proxy") or "").strip() or None
        if not username:
            return self._send_json({"ok": False, "error": "Username wajib diisi."}, 400)
        payload = {"phase": "resend", "username": username, "proxy": proxy or "",
                   "state_dir": os.path.join(DATA_DIR, "reg_pending")}
        try:
            res = LOOP.run(lambda: _run_caa_register_async(payload), timeout=250)
        except Exception as e:
            return self._send_json({"ok": False, "error": str(e)[:300]}, 400)
        if not res.get("ok"):
            return self._send_json(res, 400)
        return self._send_json(res)

    def _api_set_account_proxy(self, account_id):
        """Attach (or remove) a proxy for an already-logged-in account.

        The proxy is VERIFIED first (same probe as "Tes Proxy": it must
        reach Instagram and return the encryption key) — a dead proxy
        is refused and never stored, so an account can never end up
        silently broken behind a proxy that does not work. Only after
        the probe passes is the proxy stored encrypted (like the token)
        and applied to the live client right away — no re-login needed.
        An empty proxy removes it. Only the host is ever shown back
        to the UI.
        """
        body = self._read_json()
        proxy = (body.get("proxy") or "").strip() or None
        if proxy and not re.match(r"^https?://", proxy):
            return self._send_json({"ok": False, "error": "Format proxy harus http://user:pass@host:port (atau https://)."}, 400)
        if proxy:
            # Verify the proxy actually works before storing it.
            try:
                res = LOOP.run(lambda: test_proxy_async(proxy), timeout=60)
            except Exception as e:
                return self._send_json({"ok": False, "error": f"Proxy tidak bisa diverifikasi: {str(e)[:200]}"}, 400)
            if not res.get("ok"):
                return self._send_json({"ok": False, "error": res.get("detail") or "Proxy tidak aktif."}, 400)
            verify_detail = res.get("detail") or ""
            exit_ip = res.get("exit_ip") or ""
        else:
            verify_detail = ""
            exit_ip = ""
        with STORE_LOCK:
            accounts = load_accounts()
            acc = next((a for a in accounts if a["id"] == account_id), None)
            if acc is None:
                return self._send_json({"ok": False, "error": "akun tidak ditemukan"}, 404)
            if not self._caller_is_admin() and acc.get("owner_id") != self._caller_user_id():
                return self._send_account_forbidden()
            if proxy:
                try:
                    acc["proxy_enc"] = _encrypt_for_account(acc, proxy)
                    acc["proxy_host"] = mask_proxy(proxy)
                except Exception as e:
                    return self._send_json({"ok": False, "error": f"gagal menyimpan proxy: {e}"}, 400)
            else:
                acc.pop("proxy_enc", None)
                acc.pop("proxy_host", None)
            save_accounts(accounts)
        # Apply to the live client (no re-login needed).
        client = REGISTRY.get(account_id, acc["username"])
        applied = False
        try:
            applied = client.set_proxy(proxy)
        except Exception as e:
            log.warning("set_proxy live gagal untuk %s: %s", acc["username"], e)
        log_action(account_id, acc["username"], "proxy", "", "ok",
                   f"proxy {'dipasang (' + mask_proxy(proxy) + ')' if proxy else 'dilepas'}"
                   + ("" if applied else " — diterapkan saat sesi dipulihkan berikutnya"))
        return self._send_json({"ok": True, "account": mask_account(get_account(account_id)), "applied": applied,
                                "verify_detail": verify_detail, "exit_ip": exit_ip})

    def _api_delete_account(self, account_id):
        _, err = self._owned_account(account_id)
        if err == "forbidden":
            return self._send_account_forbidden()
        if err:
            return self._send_json({"ok": False, "error": "akun tidak ditemukan"}, 404)
        with STORE_LOCK:
            accounts = load_accounts()
            accounts = [a for a in accounts if a["id"] != account_id]
            if accounts and not any(a.get("active") for a in accounts):
                accounts[0]["active"] = True
            save_accounts(accounts)
        REGISTRY.drop(account_id)
        # Clear the deleted account from this session's selection.
        if self._auth and self._auth.get("via") == "cookie" and self._auth.get("token"):
            with SESSIONS_LOCK:
                sess = SESSIONS.get(self._auth["token"])
                if isinstance(sess, dict) and sess.get("selected_account_id") == account_id:
                    sess["selected_account_id"] = None
        return self._send_json({"ok": True})

    def _api_select_account(self, account_id):
        _, err = self._owned_account(account_id)
        if err == "forbidden":
            return self._send_account_forbidden()
        if err:
            return self._send_json({"ok": False, "error": "akun tidak ditemukan"}, 404)
        # Per-session selection (this is what routes requests now).
        if self._auth and self._auth.get("via") == "cookie" and self._auth.get("token"):
            with SESSIONS_LOCK:
                sess = SESSIONS.get(self._auth["token"])
                if isinstance(sess, dict):
                    sess["selected_account_id"] = account_id
                    self._auth["selected_account_id"] = account_id
        with STORE_LOCK:
            accounts = load_accounts()
            for a in accounts:
                # Global `active` flag kept for display compat only.
                a["active"] = (a["id"] == account_id)
            save_accounts(accounts)
        return self._send_json({"ok": True, "account": mask_account(get_account(account_id))})

    def _api_account_pic(self, account_id):
        """Fetch + cache one account's profile photo (for the account list).

        Uses the account's own live session if it has one, otherwise any
        other live session. The URL is stored in accounts.json so the
        list renders instantly next time; a failure just keeps the
        initial-letter avatar.
        """
        target, err = self._owned_account(account_id)
        if err == "forbidden":
            return self._send_account_forbidden()
        if err:
            return self._send_json({"ok": False, "error": "akun tidak ditemukan"}, 404)
        if target.get("pic"):
            return self._send_json({"ok": True, "pic": target["pic"]})
        user_id = target.get("user_id")
        if not user_id:
            return self._send_json({"ok": False, "error": "user id tidak ada"}, 400)
        accounts = self._visible_accounts()
        fetchers = [a for a in accounts if a["id"] == account_id and a.get("status") == "ok"]
        fetchers += [a for a in accounts if a["id"] != account_id and a.get("status") == "ok"]
        if not fetchers:
            return self._send_json({"ok": False, "error": "tidak ada sesi hidup untuk mengambil foto"}, 400)
        # get_user_profile gagal untuk user lain (respons kosong) — pakai
        # pencarian user yang memang mengembalikan foto profil.
        pic = None
        last_err = ""
        uname = (target.get("username") or "").lower()
        for f in fetchers:
            try:
                res = REGISTRY.call(
                    f["id"], f["username"],
                    lambda cl: cl.search_user(uname), timeout=60,
                )
                users = (res or {}).get("users") or []
                hit = next((u for u in users if (u.get("username") or "").lower() == uname), None)
                pic = (hit or (users[0] if users else {})).get("pic")
                if pic:
                    break
            except Exception as e:
                last_err = str(e)[:200]
                continue
        if not pic:
            return self._send_json({"ok": False, "error": last_err or "foto profil tidak ditemukan"}, 400)
        with STORE_LOCK:
            accounts = load_accounts()
            for a in accounts:
                if a["id"] == account_id:
                    a["pic"] = pic
                    break
            save_accounts(accounts)
        return self._send_json({"ok": True, "pic": pic})

    def _api_save_settings(self):
        # Settings are global: readable by any logged-in user, but only
        # the admin (WEB_PASSWORD gate session) may change them.
        if not self._caller_is_admin():
            return self._send_json({"ok": False, "error": "hanya admin"}, 403)
        body = self._read_json()
        settings = load_settings()
        for k in DEFAULT_SETTINGS:
            if k in body:
                settings[k] = body[k]
        save_settings(settings)
        return self._send_json({"ok": True, "settings": settings})

    def _api_add_rule(self):
        account, _, err = self._active_client()
        if err:
            return self._send_json({"ok": False, "error": err}, 400)
        body = self._read_json()
        keyword = (body.get("keyword") or "").strip()
        template = (body.get("template") or "").strip()
        if not keyword or not template:
            return self._send_json({"ok": False, "error": "keyword dan template balasan wajib diisi"}, 400)
        rule = {
            "id": uuid.uuid4().hex[:8],
            "keyword": keyword,
            "template": template,
            "enabled": True,
            "max_per_day": int(body.get("max_per_day") or 20),
        }
        with STORE_LOCK:
            rules = load_rules()
            rules.setdefault(account["id"], []).append(rule)
            save_rules(rules)
        return self._send_json({"ok": True, "rule": rule})

    def _api_delete_rule(self, rule_id):
        account, _, err = self._active_client()
        if err:
            return self._send_json({"ok": False, "error": err}, 400)
        with STORE_LOCK:
            rules = load_rules()
            rules[account["id"]] = [r for r in rules.get(account["id"], []) if r["id"] != rule_id]
            save_rules(rules)
        return self._send_json({"ok": True})

    def _api_toggle_rule(self, rule_id):
        account, _, err = self._active_client()
        if err:
            return self._send_json({"ok": False, "error": err}, 400)
        with STORE_LOCK:
            rules = load_rules()
            out = None
            for r in rules.get(account["id"], []):
                if r["id"] == rule_id:
                    r["enabled"] = not r.get("enabled", True)
                    out = r
            save_rules(rules)
        if out is None:
            return self._send_json({"ok": False, "error": "aturan tidak ditemukan"}, 404)
        return self._send_json({"ok": True, "rule": out})

    def _api_publish(self):
        account, _, err = self._active_client()
        if err:
            return self._send_json({"ok": False, "error": err}, 400)
        ctype = self.headers.get("Content-Type") or ""
        text, image_url, image_path = "", None, None
        if ctype.startswith("multipart/form-data"):
            fields, files = parse_multipart(self._read_body(), ctype)
            text = (fields.get("text") or "").strip()
            image_url = (fields.get("url") or "").strip() or None
            if "image" in files:
                fname, data = files["image"]
                ext = os.path.splitext(fname)[1].lower() or ".jpg"
                if ext not in (".jpg", ".jpeg", ".png", ".webp", ".gif"):
                    return self._send_json({"ok": False, "error": "format gambar tidak didukung (jpg/png/webp/gif)"}, 400)
                if len(data) > 8 * 1024 * 1024:
                    return self._send_json({"ok": False, "error": "gambar maksimal 8 MB"}, 400)
                os.makedirs(UPLOAD_DIR, exist_ok=True)
                image_path = os.path.join(UPLOAD_DIR, f"{uuid.uuid4().hex}{ext}")
                with open(image_path, "wb") as f:
                    f.write(data)
        else:
            body = self._read_json()
            text = (body.get("text") or "").strip()
            image_url = (body.get("url") or "").strip() or None
            if body.get("image_url"):
                image_url = body.get("image_url")
        if not text:
            return self._send_json({"ok": False, "error": "teks thread wajib diisi"}, 400)
        if len(text) > 500:
            return self._send_json({"ok": False, "error": "teks maksimal 500 karakter"}, 400)
        settings = load_settings()
        blocked = check_daily_limit(account["id"], "post", settings)
        if blocked:
            return self._send_json({"ok": False, "error": blocked}, 429)
        blocked_user = check_user_daily_limit(self._auth["user"], "post")
        if blocked_user:
            return self._send_json({"ok": False, "error": blocked_user}, 403)
        try:
            res = REGISTRY.call(
                account["id"], account["username"],
                lambda cl: cl.publish(text, image_path=image_path, url=image_url), timeout=120,
            )
        except ThreadsError as e:
            log_action(account["id"], account["username"], "post", "", "error", str(e))
            return self._send_json({"ok": False, "error": str(e)}, 400)
        link = _result_link(res)
        log_action(account["id"], account["username"], "post", "", "ok", text[:300], link=link)
        _persist_rotated_token(account["id"], account["username"])
        return self._send_json({"ok": True, "result": res, "link": link})

    def _api_post_action(self, post_id, action):
        account, _, err = self._active_client()
        if err:
            return self._send_json({"ok": False, "error": err}, 400)
        ctype = self.headers.get("Content-Type") or ""
        body, image_path = {}, None
        if ctype.startswith("multipart/form-data"):
            fields, files = parse_multipart(self._read_body(), ctype)
            body = fields
            if "image" in files:
                fname, data = files["image"]
                ext = os.path.splitext(fname)[1].lower() or ".jpg"
                if ext not in (".jpg", ".jpeg", ".png", ".webp", ".gif"):
                    return self._send_json({"ok": False, "error": "format gambar tidak didukung (jpg/png/webp/gif)"}, 400)
                if len(data) > 8 * 1024 * 1024:
                    return self._send_json({"ok": False, "error": "gambar maksimal 8 MB"}, 400)
                os.makedirs(UPLOAD_DIR, exist_ok=True)
                image_path = os.path.join(UPLOAD_DIR, f"{uuid.uuid4().hex}{ext}")
                with open(image_path, "wb") as f:
                    f.write(data)
        else:
            body = self._read_json()
        settings = load_settings()
        kind = {"like": "like", "reply": "reply", "repost": "post"}.get(action)
        if kind:
            blocked = check_daily_limit(account["id"], kind, settings)
            if blocked:
                return self._send_json({"ok": False, "error": blocked}, 429)
        if action in ("reply", "repost"):
            blocked_user = check_user_daily_limit(
                self._auth["user"], "reply" if action == "reply" else "post")
            if blocked_user:
                return self._send_json({"ok": False, "error": blocked_user}, 403)
        try:
            if action == "like":
                res = REGISTRY.call(account["id"], account["username"], lambda cl: cl.like(post_id), timeout=60)
            elif action == "unlike":
                res = REGISTRY.call(account["id"], account["username"], lambda cl: cl.unlike(post_id), timeout=60)
            elif action == "repost":
                res = REGISTRY.call(account["id"], account["username"], lambda cl: cl.repost(post_id), timeout=90)
            elif action == "delete":
                res = REGISTRY.call(account["id"], account["username"], lambda cl: cl.delete_post(post_id), timeout=90)
                if not res:
                    return self._send_json({"ok": False, "error": "hapus gagal"}, 400)
                return self._send_json({"ok": True})
            elif action == "reply":
                text = (body.get("text") or "").strip()
                if not text:
                    return self._send_json({"ok": False, "error": "teks balasan wajib diisi"}, 400)
                if len(text) > 500:
                    return self._send_json({"ok": False, "error": "teks maksimal 500 karakter"}, 400)
                url = None
                m = re.search(r"https?://\S+", text)
                if m:
                    url = m.group(0).rstrip(").,]'\"")
                res = REGISTRY.call(
                    account["id"], account["username"],
                    lambda cl: cl.publish(text, image_path=image_path, url=url, parent_post_id=post_id), timeout=120,
                )
            else:
                return self._send_json({"ok": False, "error": "aksi tidak dikenal"}, 400)
        except ThreadsError as e:
            log_action(account["id"], account["username"], action, post_id, "error", str(e))
            return self._send_json({"ok": False, "error": str(e)}, 400)
        # Save the link of the post/reply just created, so the history
        # can open it on Threads and prove it really went through.
        link = _result_link(res) if action in ("reply", "repost") else None
        log_action(account["id"], account["username"], action, post_id, "ok", (body.get("text") or "")[:300], link=link)
        _persist_rotated_token(account["id"], account["username"])
        return self._send_json({"ok": True, "result": res, "link": link})

    def _api_user_action(self, user_id, action):
        account, _, err = self._active_client()
        if err:
            return self._send_json({"ok": False, "error": err}, 400)
        try:
            if action == "follow":
                res = REGISTRY.call(account["id"], account["username"], lambda cl: cl.follow(user_id), timeout=60)
            else:
                res = REGISTRY.call(account["id"], account["username"], lambda cl: cl.unfollow(user_id), timeout=60)
        except ThreadsError as e:
            log_action(account["id"], account["username"], action, user_id, "error", str(e))
            return self._send_json({"ok": False, "error": str(e)}, 400)
        log_action(account["id"], account["username"], action, user_id, "ok")
        return self._send_json({"ok": True, "result": res})

    def _api_inbox_action(self, item_id, action):
        account, _, err = self._active_client()
        if err:
            return self._send_json({"ok": False, "error": err}, 400)
        body = self._read_json()
        # inbox item id may be "post_id:comment_id:ts" — recover the target post/comment
        post_id = body.get("post_id") or ""
        comment_id = body.get("comment_id") or ""
        target = comment_id or post_id
        if action == "ignore":
            with STORE_LOCK:
                seen = load_seen()
                seen.setdefault(account["id"], {})[item_id] = "ignored"
                save_seen(seen)
            log_action(account["id"], account["username"], "ignore", target, "ok")
            return self._send_json({"ok": True})
        settings = load_settings()
        if action == "reply":
            blocked = check_daily_limit(account["id"], "reply", settings)
            if blocked:
                return self._send_json({"ok": False, "error": blocked}, 429)
            blocked_user = check_user_daily_limit(self._auth["user"], "reply")
            if blocked_user:
                return self._send_json({"ok": False, "error": blocked_user}, 403)
            text = (body.get("text") or "").strip()
            if not text:
                return self._send_json({"ok": False, "error": "teks balasan wajib diisi"}, 400)
            if len(text) > 500:
                return self._send_json({"ok": False, "error": "teks maksimal 500 karakter"}, 400)
            if not target:
                return self._send_json({"ok": False, "error": "tidak ada target balasan"}, 400)
            try:
                res = REGISTRY.call(
                    account["id"], account["username"],
                    lambda cl: cl.publish(text, parent_post_id=target), timeout=120,
                )
            except ThreadsError as e:
                log_action(account["id"], account["username"], "reply", target, "error", str(e))
                return self._send_json({"ok": False, "error": str(e)}, 400)
            with STORE_LOCK:
                seen = load_seen()
                seen.setdefault(account["id"], {})[item_id] = "replied"
                save_seen(seen)
            log_action(account["id"], account["username"], "reply", target, "ok", text[:300])
            return self._send_json({"ok": True, "result": res})
        if action == "like":
            blocked = check_daily_limit(account["id"], "like", settings)
            if blocked:
                return self._send_json({"ok": False, "error": blocked}, 429)
            if not target:
                return self._send_json({"ok": False, "error": "tidak ada target like"}, 400)
            try:
                res = REGISTRY.call(account["id"], account["username"], lambda cl: cl.like(target), timeout=60)
            except ThreadsError as e:
                log_action(account["id"], account["username"], "like", target, "error", str(e))
                return self._send_json({"ok": False, "error": str(e)}, 400)
            with STORE_LOCK:
                seen = load_seen()
                seen.setdefault(account["id"], {})[item_id] = "liked"
                save_seen(seen)
            log_action(account["id"], account["username"], "like", target, "ok")
            return self._send_json({"ok": True, "result": res})
        return self._send_json({"ok": False, "error": "aksi tidak dikenal"}, 400)


# ------------------------------------------------------------ auto-reply ---

def auto_reply_worker(stop_event: threading.Event):
    """Every 5 minutes per account: check replies, answer matching rules."""
    while not stop_event.wait(300):
        try:
            settings = load_settings()
            if not settings.get("auto_reply_enabled"):
                continue
            accounts = load_accounts()
            rules_all = load_rules()
            for account in accounts:
                if stop_event.is_set():
                    return
                rules = [r for r in rules_all.get(account["id"], []) if r.get("enabled")]
                if not rules:
                    continue
                try:
                    _auto_reply_one_account(account, rules, settings)
                except Exception as e:
                    log.warning("auto-reply %s: %s", account["username"], e)
        except Exception as e:
            log.warning("auto-reply worker: %s", e)


def _auto_reply_one_account(account, rules, settings):
    try:
        res = REGISTRY.call(
            account["id"], account["username"],
            lambda cl: cl.notifications(), timeout=90,
        )
    except ThreadsError as e:
        log.warning("auto-reply %s notifications: %s", account["username"], e)
        return
    seen = load_seen()
    acct_seen = seen.setdefault(account["id"], {})
    dirty = False
    for item in res.get("items", [])[:20]:
        iid = item["id"]
        if acct_seen.get(iid):
            continue
        text = (item.get("text") or "").lower()
        author = item.get("author") or "seseorang"
        matched = None
        for r in rules:
            if r.get("keyword", "").lower() in text:
                matched = r
                break
        if not matched:
            continue
        # daily caps: rule cap + global reply cap (manual + auto replies share it)
        if count_actions_today(account["id"], "auto_reply") >= matched.get("max_per_day", 20):
            continue
        used_replies = count_actions_today(account["id"], "reply") + count_actions_today(account["id"], "auto_reply")
        if used_replies >= settings.get("max_replies_per_day", 100):
            break
        reply_text = matched["template"].replace("{author}", author)[:500]
        target = item.get("comment_id") or item.get("post_id")
        if not target:
            continue
        # random delay 20-60s between auto actions (anti-ban)
        delay = random.uniform(
            settings.get("min_delay_seconds", 20),
            max(60, settings.get("min_delay_seconds", 20)),
        )
        time.sleep(delay)
        try:
            REGISTRY.call(
                account["id"], account["username"],
                lambda cl, t=reply_text, p=target: cl.publish(t, parent_post_id=p),
                timeout=120,
            )
            acct_seen[iid] = "auto_replied"
            dirty = True
            log_action(account["id"], account["username"], "auto_reply", target, "ok",
                       f"rule:{matched['keyword']} -> {reply_text[:120]}")
        except ThreadsError as e:
            log_action(account["id"], account["username"], "auto_reply", target, "error", str(e))
            acct_seen[iid] = "auto_failed"
            dirty = True
    if dirty:
        with STORE_LOCK:
            save_seen(seen)


def auto_comment_worker(stop_event: threading.Event):
    """Auto-comment affiliate links on busy, beauty-related feed posts.

    Runs every 30 minutes per account, posts at most ONE comment per
    run (so the daily cap spreads across the day like a human), only
    on posts that mention a beauty keyword AND have enough engagement,
    and never twice on the same post. Disabled by default.
    """
    products = load_products()
    while not stop_event.wait(1800):
        try:
            settings = load_settings()
            if not settings.get("auto_comment_enabled") or not products:
                continue
            for account in load_accounts():
                if stop_event.is_set():
                    return
                try:
                    _auto_comment_one_account(account, settings, products)
                except Exception as e:
                    log.warning("auto-comment %s: %s", account["username"], e)
        except Exception as e:
            log.warning("auto-comment worker: %s", e)


def _auto_comment_one_account(account, settings, products):
    max_per_day = settings.get("max_comments_per_day", 3)
    if count_actions_today(account["id"], "auto_comment") >= max_per_day:
        return
    min_eng = settings.get("comment_min_engagement", 20)
    seen = load_seen_comments()
    acct_seen = seen.setdefault(account["id"], {})
    # fetch up to 3 fresh feed pages, look for a beauty post we have
    # not commented on yet
    max_id = None
    target = None
    target_kw = None
    for _ in range(3):
        try:
            res = REGISTRY.call(
                account["id"], account["username"],
                lambda cl, m=max_id: cl.timeline(max_id=m), timeout=90,
            )
        except ThreadsError as e:
            log.warning("auto-comment %s feed: %s", account["username"], e)
            return
        for p in res.get("items") or []:
            pid = p.get("id")
            if not pid or acct_seen.get(pid):
                continue
            author = (p.get("author") or {}).get("username") or ""
            if author.lower() == account["username"].lower():
                continue
            eng = (p.get("like_count") or 0) + (p.get("reply_count") or 0)
            if eng < min_eng:
                continue
            text = (p.get("text") or "").lower()
            hit = _kw_hit(text, BEAUTY_KEYWORDS)
            if not hit:
                continue
            target = p
            target_kw = hit[0]
            break
        if target:
            break
        max_id = res.get("next_max_id")
        if not res.get("more_available") or not max_id:
            break
    if not target:
        return
    # pick a product whose keywords overlap the post (fall back to any)
    text = (target.get("text") or "").lower()
    best = None
    best_score = 0
    for prod in products:
        score = len(_kw_hit(text, prod.get("keywords") or []))
        if score > best_score:
            best_score = score
            best = prod
    if not best or best_score < 1:
        # no product actually matches this post — skip, do not force one
        acct_seen[target["id"]] = "auto_skipped"
        save_seen_comments(seen)
        return
    kw = target_kw
    for k in _kw_hit(text, best.get("keywords") or []):
        kw = k
        break
    tmpl = random.choice(COMMENT_TEMPLATES)
    comment = tmpl.format(
        kw=kw, product=best.get("display_name") or best["short_name"], price=best.get("price") or "",
        link=best["link"],
    )[:500]
    # human-like pause before posting (1-2 hours is overkill inside a
    # 30-min loop; the loop itself spreads comments across the day)
    time.sleep(random.uniform(20, 90))
    try:
        res = REGISTRY.call(
            account["id"], account["username"],
            lambda cl, t=comment, p=target["id"]: cl.publish(t, parent_post_id=p),
            timeout=120,
        )
        acct_seen[target["id"]] = "auto_commented"
        save_seen_comments(seen)
        link = _result_link(res)
        log_action(account["id"], account["username"], "auto_comment",
                   target["id"], "ok", f"{kw} -> {best['short_name'][:80]}",
                   link=link)
    except ThreadsError as e:
        acct_seen[target["id"]] = "auto_failed"
        save_seen_comments(seen)
        log_action(account["id"], account["username"], "auto_comment",
                   target["id"], "error", str(e))


# ------------------------------------------------------------- startup -----

def restore_accounts():
    """Restore saved sessions from encrypted tokens; verify each lightly."""
    accounts = load_accounts()
    if not accounts:
        log.info("no saved accounts")
        return
    for a in accounts:
        try:
            token = _decrypt_for_account(a, a["token_enc"])
        except Exception as e:
            log.warning("account %s: token tidak bisa didekripsi: %s", a["username"], e)
            set_account_status(a["id"], "error", "token tidak bisa didekripsi")
            continue
        client = REGISTRY.get(a["id"], a["username"])
        settings = None
        enc_settings = a.get("session_settings_enc")
        if enc_settings:
            try:
                settings = json.loads(_decrypt_for_account(a, enc_settings))
            except Exception as e:
                log.warning("account %s: session settings tidak bisa didekripsi: %s", a["username"], e)
        proxy = None
        enc_proxy = a.get("proxy_enc")
        if enc_proxy:
            try:
                proxy = _decrypt_for_account(a, enc_proxy)
            except Exception as e:
                log.warning("account %s: proxy tidak bisa didekripsi: %s", a["username"], e)
        try:
            ok = LOOP.run(
                lambda: client.restore(token, a.get("user_id") or "", a["username"], settings=settings, proxy=proxy),
                timeout=90,
            )
        except Exception as e:
            log.warning("account %s restore: %s", a["username"], e)
            set_account_status(a["id"], "error", str(e)[:200])
            continue
        if ok:
            set_account_status(a["id"], "ok", "")
            log.info("account %s restored OK", a["username"])
        else:
            log.warning("account %s token expired", a["username"])


def main():
    global MASTER_KEY, REGISTRY
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(SESSIONS_DIR, exist_ok=True)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    MASTER_KEY = crypto_store.get_or_create_master_key(DATA_DIR)
    REGISTRY = ClientRegistry(DATA_DIR)
    users_store.ensure_admin(DATA_DIR)
    log.info("starting threads-app on %s:%d", HOST, PORT)
    restore_accounts()
    stop_event = threading.Event()
    worker = threading.Thread(target=auto_reply_worker, args=(stop_event,), name="auto-reply", daemon=True)
    worker.start()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        server.server_close()


if __name__ == "__main__":
    main()
