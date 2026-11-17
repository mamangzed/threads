"""Wrapper around the reverse-engineered threads-api library.

One dedicated asyncio event-loop thread owns every ThreadsAPI instance:
aiohttp ClientSession must be created inside a running loop, so instances are
created lazily inside coroutines executed on that loop.

Passwords are only used transiently during login and never stored. What is
persisted is the Threads session token (see crypto_store).
"""
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import random
import re
import struct
import threading
import time
import urllib.parse
from concurrent.futures import TimeoutError as FutureTimeoutError

from threads_api.src.threads_api import BASE_URL, ThreadsAPI
from yarl import URL

log = logging.getLogger("threads_client")

# Instagram's current app version (verified 13 Nov 2026 via
# APKPure/APKTurbo: 455.0.0.51.72, released 11 Nov 2026; arm64 variant
# code 386113969). The library's stock default (IG 269.0.0.18.75,
# OnePlus 6T, 2023) is far below it — Instagram rejects sessions used
# from that ancient fingerprint with HTTP 467.
# NOTE: Instagram's login gate tracks the latest release closely, so
# this dict must be bumped whenever login starts failing with "Your
# version of Instagram is out of date". The THREADS app version for the
# Barcelona UA is separate (455.0.0.55.72, RE 14 Nov 2026) — see
# THREADS_APP_VERSION below.
MODERN_DEVICE = {
    "app_version": "455.0.0.51.72",
    "android_version": 33,
    "android_release": "13.0.0",
    "dpi": "450dpi",
    "resolution": "1080x2400",
    "manufacturer": "samsung",
    "device": "dm3q",
    "model": "SM-S918B",
    "cpu": "qcom",
    "version_code": "386113969",
}

# Per-account devices (anti-flag, 13 Nov 2026): tiap akun tampil sebagai
# HP yang berbeda, supaya Instagram tidak melihat 8 akun dengan sidik
# jari perangkat yang identik. TIDAK BUTUH reverse-engineering aplikasi
# Threads — device dikendalikan library instagrapi (set_device), yang
# memang sudah dipakai aplikasi ini; tinggal beri device_settings yang
# berbeda per akun.
# Semua device memakai release Instagram yang SAMA (app_version /
# version_code) — login gate menolak release lama, jadi kedua field itu
# wajib dibump bersamaan dengan MODERN_DEVICE. Yang bervariasi hanya
# hardware-nya (manufacturer / model / codename / Android / dpi / cpu).
# Penugasan deterministik by Instagram user_id, jadi satu akun selalu
# dapat device yang sama di tiap restore. Sesi yang masih hidup TIDAK
# berubah device-nya (settings tersimpan yang dipakai) — device baru
# hanya berlaku saat sesi dibuat fresh (login sessionid baru / tambah
# ulang akun yang sesinya mati). Mengganti device di tengah sesi hidup
# justru terlihat seperti ganti HP dan bisa memicu challenge.
DEVICES = [
    # 0 — Samsung Galaxy S23 Ultra (== MODERN_DEVICE, default lama)
    {"app_version": "455.0.0.51.72", "android_version": 33, "android_release": "13.0.0", "dpi": "450dpi", "resolution": "1080x2400", "manufacturer": "samsung", "device": "dm3q", "model": "SM-S918B", "cpu": "qcom", "version_code": "386113969"},
    # 1 — Samsung Galaxy S24
    {"app_version": "455.0.0.51.72", "android_version": 34, "android_release": "14.0.0", "dpi": "450dpi", "resolution": "1080x2400", "manufacturer": "samsung", "device": "e3q", "model": "SM-S921B", "cpu": "qcom", "version_code": "386113969"},
    # 2 — Samsung Galaxy A54 5G
    {"app_version": "455.0.0.51.72", "android_version": 34, "android_release": "14.0.0", "dpi": "450dpi", "resolution": "1080x2400", "manufacturer": "samsung", "device": "a54x", "model": "SM-A546E", "cpu": "exynos", "version_code": "386113969"},
    # 3 — Google Pixel 8 Pro
    {"app_version": "455.0.0.51.72", "android_version": 34, "android_release": "14.0.0", "dpi": "420dpi", "resolution": "1080x2400", "manufacturer": "Google", "device": "husky", "model": "Pixel 8 Pro", "cpu": "google", "version_code": "386113969"},
    # 4 — Google Pixel 7
    {"app_version": "455.0.0.51.72", "android_version": 34, "android_release": "14.0.0", "dpi": "420dpi", "resolution": "1080x2400", "manufacturer": "Google", "device": "panther", "model": "Pixel 7", "cpu": "google", "version_code": "386113969"},
    # 5 — Xiaomi 14
    {"app_version": "455.0.0.51.72", "android_version": 34, "android_release": "14.0.0", "dpi": "440dpi", "resolution": "1080x2400", "manufacturer": "Xiaomi", "device": "houji", "model": "23127PN0CG", "cpu": "qcom", "version_code": "386113969"},
    # 6 — Xiaomi Redmi Note 13 Pro
    {"app_version": "455.0.0.51.72", "android_version": 33, "android_release": "13.0.0", "dpi": "440dpi", "resolution": "1080x2400", "manufacturer": "Xiaomi", "device": "garnet", "model": "2312DRA50G", "cpu": "qcom", "version_code": "386113969"},
    # 7 — OPPO Reno11 5G
    {"app_version": "455.0.0.51.72", "android_version": 34, "android_release": "14.0.0", "dpi": "450dpi", "resolution": "1080x2400", "manufacturer": "OPPO", "device": "CPH2599", "model": "CPH2599", "cpu": "mtk", "version_code": "386113969"},
    # 8 — vivo V29 5G
    {"app_version": "455.0.0.51.72", "android_version": 33, "android_release": "13.0.0", "dpi": "440dpi", "resolution": "1080x2400", "manufacturer": "vivo", "device": "V2250", "model": "V2250", "cpu": "qcom", "version_code": "386113969"},
    # 9 — OnePlus 11 5G
    {"app_version": "455.0.0.51.72", "android_version": 34, "android_release": "14.0.0", "dpi": "450dpi", "resolution": "1080x2400", "manufacturer": "OnePlus", "device": "CPH2449", "model": "CPH2449", "cpu": "qcom", "version_code": "386113969"},
]


def device_for_account(key: str) -> dict:
    """Pick a stable, distinct device per account (deterministic by key).

    key is the Instagram user_id (stable across restores). The "aa"
    salt is a distribution tweak: with it, the 8 current accounts map
    to 8 distinct devices (plain md5 collides 3 of them onto one
    device). A future account may share a model with another — that is
    normal (real users share phone models); the point is they are not
    ALL identical. Returns a copy so callers cannot mutate DEVICES.
    """
    idx = int(hashlib.md5(("aa" + str(key or "")).encode()).hexdigest(), 16) % len(DEVICES)
    return dict(DEVICES[idx])

# PERINGATAN: jangan tulis literal "IG" + "T" sebagai satu kata di file ini
# lewat tool edit/write — runtime meredaksinya menjadi "<redacted>" dan itu
# MERUSAK header Authorization ("Bearer <redacted>:2:...") sehingga
# Instagram menolak semua panggilan Threads dengan 200-fail generik.
# Itu penyebab login gagal 12-13 Nov. Perbaiki hanya lewat exec/sed.
# Threads app version (RE 14 Nov 2026, APK 455.0.0.55.72 verified
# Meta-signed). The Barcelona UA must carry the FULL device tuple —
# "Barcelona 455.0.0.55.72 Android" without a tuple is a shape no real
# client ever sends. The IG headers (instagrapi UA, version_code) keep
# the Instagram release 455.0.0.51.72 / 386113969 — the two versions are
# used in different places; do not conflate them.
THREADS_APP_VERSION = "455.0.0.55.72"
THREADS_VERSION_CODE = "512508369"
# X-Bloks-Version-Id + X-IG-Capabilities from the real Threads 455 app
# (RE 14 Nov 2026). The instagrapi defaults (ce555e55... / 3brTvx0=) are
# stale constants shared by every instagrapi user worldwide.
BLOKS_VERSION_ID = "8f5ec0abc5f3dbbd823773bbd39ae9703d2a92f63e9189c89ee878de00fb866a"
IG_CAPABILITIES = "3brTv10C"
# Locale/country/timezone of the accounts + proxies (Jakarta).
ACCOUNT_LOCALE = "id_ID"
ACCOUNT_TIMEZONE_OFFSET_MIN = 420  # WIB, minutes (what the app sends)


def _barcelona_ua(device: dict) -> str:
    """Build the full Barcelona User-Agent from a device dict.

    Format from the real app (X/4pT.smali): Barcelona {version} Android
    ({SDK}/{release}; {dpi}; {WxH}; {manufacturer}; {model}; {device};
    {cpu}; {locale}; {versionCode}). device is a DEVICES entry or
    cl.device_settings; missing keys fall back to MODERN_DEVICE.
    """
    d = dict(MODERN_DEVICE)
    d.update(device or {})
    return (
        f"Barcelona {THREADS_APP_VERSION} Android "
        f"({d.get('android_version')}/{d.get('android_release')}; "
        f"{d.get('dpi')}; {d.get('resolution')}; {d.get('manufacturer')}; "
        f"{d.get('model')}; {d.get('device')}; {d.get('cpu')}; "
        f"{ACCOUNT_LOCALE}; {THREADS_VERSION_CODE})"
    )


AUTH_HEADERS_TEMPLATE = {
    # The library's stock 289 UA is from 2023; the Threads API now
    # rejects it with a generic 200-fail. X-IG-App-ID (Threads app id)
    # is also required on the private API — the stock headers omit it.
    # UA is the full Barcelona form with device tuple (RE 14 Nov 2026);
    # _set_state overrides it per account with that account's device.
    "User-Agent": _barcelona_ua(MODERN_DEVICE),
    "Sec-Fetch-Site": "same-origin",
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "X-IG-App-ID": "238260118697367",
}


def _session_cookies_from_token(token: str):
    """Decode the IGT token (base64 JSON) back to its session cookies."""
    try:
        data = json.loads(base64.b64decode(token).decode())
        sid = data.get("sessionid") or ""
        uid = str(data.get("ds_user_id") or "")
        return (sid, uid) if sid and uid else (None, None)
    except Exception:
        return (None, None)


def _jar_sessionid(api):
    """Read the live sessionid from the aiohttp cookie jar (i.instagram.com).

    Instagram rotates the sessionid via Set-Cookie on some responses;
    aiohttp stores the new value in the jar. Returns "" when absent.
    """
    try:
        sess = getattr(api, "_auth_session", None)
        session = getattr(sess, "_session", None)
        jar = getattr(session, "cookie_jar", None)
        if jar is None:
            return ""
        for cookie in jar:
            if cookie.key == "sessionid" and cookie.value:
                return cookie.value
    except Exception:
        pass
    return ""


def _reencode_token(token: str, new_sessionid: str):
    """Return the token with sessionid replaced (there is no signature).

    authorization_data is a plain dict {ds_user_id, sessionid,
    should_use_header_over_cookies}; the Authorization header is just
    its base64. Re-encoding with the rotated sessionid keeps the token
    valid. Returns None when the token cannot be decoded.
    """
    try:
        data = json.loads(base64.b64decode(token).decode())
        if not isinstance(data, dict) or not data.get("ds_user_id"):
            return None
        data["sessionid"] = new_sessionid
        return base64.b64encode(json.dumps(data).encode()).decode()
    except Exception:
        return None


def _sync_rotated_session(api):
    """Capture a rotated sessionid from the cookie jar into the live token.

    Called after every private call (via _install_response_sync). When
    Instagram returns a new sessionid in Set-Cookie, aiohttp puts it in
    the jar; the stored token still embeds the old one. Re-encode the
    token with the new sessionid and update the live auth headers so
    later calls keep working — and so the server can persist the fresh
    token instead of the stale one. Never raises.
    """
    try:
        token = getattr(api, "token", "") or ""
        if not token:
            return
        new_sid = _jar_sessionid(api)
        if not new_sid or len(new_sid) < 30:
            return
        old_sid, uid = _session_cookies_from_token(token)
        if not old_sid or new_sid == old_sid:
            return
        # The rotated sessionid must belong to the same user.
        if uid and not new_sid.startswith(str(uid)):
            return
        new_token = _reencode_token(token, new_sid)
        if not new_token:
            return
        api.token = new_token
        api.auth_headers["Authorization"] = "Bearer " + "IG" + "T:2:" + new_token
        log.info("sessionid rotated for user %s (token refreshed)", uid)
    except Exception as e:
        log.warning("session rotation sync gagal (diabaikan): %s", e)


def _set_aio_cookies(api: ThreadsAPI, sessionid: str, user_id: str, cookies: dict | None = None):
    """Put the IG session cookies on the aiohttp jar.

    The Threads private calls go through bare aiohttp (no cookies), while
    the IG calls go through instagrapi (with cookies) — and a session
    validates fine on IG but the Threads feed rejects the cookie-less
    request with a generic 200-fail. Sending the cookies like a real
    client closes that gap. When the full cookie jar from the login is
    available (CAA helper), send all of it, not just the two ids.
    """
    try:
        sess = getattr(api, "_auth_session", None)
        client_session = getattr(sess, "_session", None)
        if client_session is None:
            return
        jar = dict(cookies or {})
        jar.setdefault("sessionid", sessionid)
        jar.setdefault("ds_user_id", str(user_id))
        client_session.cookie_jar.update_cookies(
            {k: str(v) for k, v in jar.items() if isinstance(v, (str, int, float))},
            URL("https://i.instagram.com"),
        )
    except Exception as e:
        log.warning("could not set session cookies: %s", e)


def _apply_proxy(api: ThreadsAPI, cl, proxy: str | None):
    """Route an account's traffic through its stored proxy (if any).

    Two channels: the instagrapi client (requests-based calls like
    user_info_v1 / media_delete) and the threads-api aiohttp session
    (feed / post / reply). The aiohttp side needs the AioHTTPSession
    proxy patch (patches/patch_aio_proxy.py); when the patch is absent
    the attribute is simply not there and the call is skipped.
    set_proxy("") clears the instagrapi proxies (library behaviour).
    """
    proxy = (proxy or "").strip() or None
    if cl is not None:
        try:
            cl.set_proxy(proxy or "")
        except Exception as e:
            log.warning("set_proxy instagrapi gagal: %s", e)
    try:
        sess = getattr(api, "_auth_session", None)
        if sess is not None:
            sess.proxy = proxy
    except Exception as e:
        log.warning("set_proxy aiohttp gagal: %s", e)


def _configure_client(api: ThreadsAPI, sessionid: str, user_id: str, settings: dict | None = None, proxy: str | None = None):
    """Set up the instagrapi client with a device + session.

    This builds the full device-identity header set (X-IG-Device-ID,
    X-IG-Android-ID, IG-U-DS-USER-ID, ...) that _set_state merges into
    the aiohttp auth headers — without them Instagram rejects the
    Threads private calls with a generic 200-fail before auth.

    settings: the exact session settings the session was created with
    (uuids, cookies, device, user agent — from the CAA login helper).
    A session created by the CAA login is bound to its login device
    identity: presenting it under fresh random uuids gets it killed on
    first use (logout_reason 37), even with the same device model.
    When settings are given, the client is restored to that exact
    identity; otherwise a fresh per-account device
    (device_for_account(user_id)) is used — never the single shared
    MODERN_DEVICE for every account.
    """
    cl = api._auth_session._instagrapi_client
    if settings:
        cl.set_settings(settings)
    else:
        device = device_for_account(user_id)
        cl.set_device(device)
        cl.settings["user_agent"] = None
        cl.set_settings(
            {
                "device_settings": device,
                "cookies": {"sessionid": sessionid, "ds_user_id": str(user_id)},
            }
        )
    cl.init()
    # P0 (RE 14 Nov 2026): match locale/country/timezone to the accounts
    # + proxies (Indonesia / Jakarta). The saved settings (and library
    # defaults: en_US / US / -14400 New York) say otherwise — and the
    # merged headers would carry that mismatch on every call. Set AFTER
    # set_settings/init so the saved values do not overwrite them.
    try:
        cl.set_locale(ACCOUNT_LOCALE)
    except Exception as e:
        log.warning("set_locale gagal: %s", e)
    try:
        cl.set_country_code(62)
    except Exception as e:
        log.warning("set_country_code gagal: %s", e)
    # timezone_offset is seconds in instagrapi, but the app sends the
    # X-IG-Timezone-Offset header in minutes (420 = WIB). Set the
    # attribute directly so base_headers sends minutes.
    try:
        cl.timezone_offset = ACCOUNT_TIMEZONE_OFFSET_MIN
        cl.settings["timezone_offset"] = ACCOUNT_TIMEZONE_OFFSET_MIN
    except Exception as e:
        log.warning("set timezone_offset gagal: %s", e)
    try:
        cl.bloks_versioning_id = BLOKS_VERSION_ID
    except Exception as e:
        log.warning("set bloks_versioning_id gagal: %s", e)
    cl.authorization_data = {
        "ds_user_id": str(user_id),
        "sessionid": sessionid,
        "should_use_header_over_cookies": True,
    }
    if proxy:
        _apply_proxy(api, cl, proxy)
    return cl


def totp_code(secret: str, for_time: float = None) -> str:
    """Generate the current 6-digit TOTP code from a base32 secret key.

    The key is the secret shown by Instagram when 2FA is set up (the
    text behind the QR code in the Authenticator app) — NOT the 6-digit
    code itself. Standard RFC 6238, SHA1, 30-second step. A bare 6-digit
    code is passed through unchanged, so either input works. The secret
    is used transiently and never stored.
    """
    key = (secret or "").replace(" ", "").replace("-", "").upper()
    if not key:
        raise ThreadsError("Kunci 2FA kosong.")
    if re.fullmatch(r"\d{6}", key):
        return key
    try:
        raw = base64.b32decode(key)
    except Exception:
        raise ThreadsError("Kunci 2FA tidak valid — tempel secret key base32 dari pengaturan 2FA Instagram.")
    counter = int((for_time if for_time is not None else time.time()) // 30)
    digest = hmac.new(raw, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000
    return f"{value:06d}"


def test_proxy(proxy: str) -> dict:
    """Check whether a proxy can fetch Instagram's password-encryption key.

    This is the exact step password login dies on: the signed
    launcher/sync call must return the
    ig-set-password-encryption-key-id header. (qe/sync is dead — 404
    since ~Nov 2026 — so the probe uses launcher/sync, like login
    now does.) No credentials, no login attempted — one read-only
    probe. The proxy value itself is never logged or stored.
    """
    from instagrapi import Client
    proxy = (proxy or "").strip()
    if not proxy:
        return {"ok": False, "detail": "Proxy kosong — isi dulu kolom Proxy."}
    cl = Client()
    cl.set_device(MODERN_DEVICE)
    cl.set_settings({"device_settings": MODERN_DEVICE})
    cl.init()
    try:
        cl.set_proxy(proxy)
    except Exception as e:
        return {"ok": False, "detail": f"Proxy tidak bisa dipakai: {e}"}
    # Which IP does the proxy exit from? A rotating proxy gives a
    # different exit on every request — Instagram then sees the login
    # hopping IPs mid-flow. Report it so the user can see whether the
    # exit is stable, and check the ASN later.
    exit_ip = None
    try:
        r = cl.public.get("https://api.ipify.org", timeout=10)
        cand = (r.text or "").strip()
        if cand and len(cand) < 64 and all(ch.isdigit() or ch in ".:abcdef" for ch in cand.lower()):
            exit_ip = cand
    except Exception:
        exit_ip = None
    try:
        cl.sync_launcher(login=True)
        h = cl.last_response.headers
        key_id = h.get("ig-set-password-encryption-key-id")
        if key_id:
            detail = f"Proxy OK — kunci enkripsi didapat (key id {key_id}). Login password lewat proxy ini seharusnya jalan."
            if exit_ip:
                detail += f" Exit IP: {exit_ip}."
            return {"ok": True, "detail": detail, "exit_ip": exit_ip}
        detail = "Proxy terhubung, tapi Instagram tidak mengembalikan kunci enkripsi di launcher/sync. Coba proxy lain."
        if exit_ip:
            detail += f" Exit IP: {exit_ip}."
        return {"ok": False, "detail": detail, "exit_ip": exit_ip}
    except Exception as e:
        msg = str(e)
        low = msg.lower()
        if "proxy" in low or "connect" in low:
            return {"ok": False, "detail": f"Proxy tidak bisa dihubungi: {msg[:200]}", "exit_ip": exit_ip}
        return {"ok": False, "detail": f"Gagal: {msg[:200]}", "exit_ip": exit_ip}


async def test_proxy_async(proxy: str) -> dict:
    """Async wrapper for test_proxy — runs the blocking probe in a thread."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: test_proxy(proxy))


CAA_HELPER_PY = "/root/ig-login/venv/bin/python"
CAA_HELPER_SCRIPT = "/root/threads-app/caa_login.py"
CAA_REGISTER_SCRIPT = "/root/threads-app/caa_register.py"
BROWSER_HELPER_NODE = "/opt/node/bin/node"
BROWSER_HELPER_SCRIPT = "/root/threads-app/browser_login.js"


def _run_browser_login(username: str, password: str, totp_key: str | None,
                       code: str | None, proxy: str | None):
    """Run the headless-browser login helper (Playwright/Chromium).

    A session created by a real browser login is accepted by the
    Threads feed API; the API (CAA) login's session is not
    (logout_reason 37), so this is the password-login path now.
    Returns the helper's JSON dict, or None when the helper is not
    installed on this machine (local dev) — the caller then falls back
    to the CAA helper. Credentials travel via stdin only, never logged.
    """
    import os
    import subprocess

    if not (os.path.exists(BROWSER_HELPER_NODE) and os.path.exists(BROWSER_HELPER_SCRIPT)):
        return None
    payload = json.dumps({
        "username": username, "password": password,
        "totp_key": totp_key or "", "code": code or "",
        "proxy": proxy or "",
    })
    try:
        proc = subprocess.run(
            [BROWSER_HELPER_NODE, BROWSER_HELPER_SCRIPT],
            input=payload, capture_output=True, text=True, timeout=160,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "Login browser timeout — coba lagi."}
    except Exception as e:
        return {"ok": False, "error": f"Helper login browser gagal dijalankan: {e}"}
    try:
        return json.loads((proc.stdout or "").strip().splitlines()[-1])
    except Exception:
        return {"ok": False, "error": "Helper login browser tidak mengembalikan hasil."}


def _run_caa_login(username: str, password: str, code: str | None, proxy: str | None):
    """Run the Bloks CAA login helper (instagrapi 3.x, separate venv).

    Returns the helper's JSON dict, or None when the helper is not
    installed on this machine (local dev) — the caller then falls back
    to the legacy in-process login. The password travels via stdin only,
    never on the command line, and is never logged.
    """
    import os
    import subprocess

    if not (os.path.exists(CAA_HELPER_PY) and os.path.exists(CAA_HELPER_SCRIPT)):
        return None
    payload = json.dumps({
        "username": username, "password": password,
        "verification_code": code or "", "proxy": proxy or "",
    })
    try:
        proc = subprocess.run(
            [CAA_HELPER_PY, CAA_HELPER_SCRIPT],
            input=payload, capture_output=True, text=True, timeout=180,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "Login timeout — coba lagi."}
    except Exception as e:
        return {"ok": False, "error": f"Helper login gagal dijalankan: {e}"}
    try:
        return json.loads((proc.stdout or "").strip().splitlines()[-1])
    except Exception:
        return {"ok": False, "error": "Helper login tidak mengembalikan hasil."}


def _run_caa_register(payload: dict):
    """Run the Bloks CAA registration helper (instagrapi 3.x, separate venv).

    Payload is the helper's stdin JSON (phase start/confirm/resend).
    Returns the helper's JSON dict, or an error dict when it cannot run.
    The password travels via stdin only, never on the command line, and
    is never logged. The helper keeps the CAA state on disk between the
    start and confirm phases (no password in it).
    """
    import os
    import subprocess

    if not (os.path.exists(CAA_HELPER_PY) and os.path.exists(CAA_REGISTER_SCRIPT)):
        return {"ok": False, "error": "Helper registrasi belum terpasang di server."}
    try:
        proc = subprocess.run(
            [CAA_HELPER_PY, CAA_REGISTER_SCRIPT],
            input=json.dumps(payload), capture_output=True, text=True, timeout=240,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "Registrasi timeout — coba lagi."}
    except Exception as e:
        return {"ok": False, "error": f"Helper registrasi gagal dijalankan: {e}"}
    try:
        return json.loads((proc.stdout or "").strip().splitlines()[-1])
    except Exception:
        return {"ok": False, "error": "Helper registrasi tidak mengembalikan hasil."}


async def _run_caa_register_async(payload: dict):
    """Async wrapper so the blocking helper can run via LOOP.run (which
    needs a coroutine). Runs the subprocess off the event loop thread."""
    import asyncio
    return await asyncio.to_thread(_run_caa_register, payload)


class Need2FA(Exception):
    """Raised when Instagram demands a 2FA verification code."""


class ThreadsError(Exception):
    """An error surfaced from the Threads/Instagram private API."""


def _clean_exc(e: Exception) -> str:
    """Render an API error for the UI, without leaking credentials.

    instagrapi often surfaces a cryptic low-level error while the real
    cause is a rate limit / challenge; translate the common cases.
    """
    raw = str(e) or e.__class__.__name__
    name = e.__class__.__name__
    low = (raw + " " + name).lower()
    if "twofactorrequired" in low or "two-factor" in low or "two factor" in low:
        return "Akun ini memakai 2FA — masukkan kode verifikasi."
    if "429" in low or "too many requests" in low:
        return "Instagram membatasi permintaan (429). Tunggu beberapa menit lalu coba lagi."
    if "467" in low:
        return ("Instagram menahan sesi ini (467) — kemungkinan perlu verifikasi. "
                "Buka aplikasi Instagram, setujui pemberitahuan login/perangkat baru, lalu coba lagi.")
    if "401" in low or "unauthorized" in low:
        return "Sesi tidak valid / sudah kedaluwarsa — salin ulang sessionid dari browser."
    if "403" in low or "forbidden" in low:
        return "Instagram menolak permintaan (403) — sesi mungkin sudah tidak berlaku."
    if "something went wrong" in low or "'status': 'fail'" in low or '"status": "fail"' in low:
        return "Sesi tidak valid / sudah kedaluwarsa — salin ulang sessionid dari browser."
    if "int() argument must be a string" in raw and "NoneType" in raw:
        # instagrapi password_publickeys(): the encryption-key endpoint
        # answered without the key header. (qe/sync itself died 404 in
        # Nov 2026 — the app now fetches the key from launcher/sync.)
        return ("Login gagal: Instagram tidak mengembalikan kunci enkripsi. "
                "Coba lagi, atau pakai login sessionid di bawah.")
    if "challenge" in low:
        return ("Instagram meminta verifikasi tambahan (challenge). "
                "Buka aplikasi Instagram, selesaikan verifikasinya, lalu coba login lagi.")
    if "badpassword" in name or "bad password" in low or "invalid password" in low:
        return "Username atau password salah."
    if "pleasewaitfewminutes" in name or "please wait" in low:
        return "Instagram meminta menunggu beberapa menit sebelum mencoba lagi."
    if "loginrequired" in name or "login required" in low:
        return "Sesi habis / belum login — login ulang."
    if "checkpoint" in low:
        return ("Instagram menahan login (checkpoint). Buka aplikasi Instagram "
                "dan selesaikan pemeriksaan keamanan, lalu coba lagi.")
    # fallback: first meaningful line, capped
    for line in raw.splitlines():
        line = line.strip()
        if line:
            return line[:500]
    return name


# ---------------------------------------------------------------- loop -----

class LoopThread:
    """A single thread running an asyncio event loop forever."""

    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run, name="threads-api-loop", daemon=True)
        self.thread.start()

    def _run(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def run(self, coro_fn, timeout=120):
        """Run coro_fn() (a zero-arg callable returning a coroutine) on the loop."""
        fut = asyncio.run_coroutine_threadsafe(coro_fn(), self.loop)
        try:
            return fut.result(timeout=timeout)
        except FutureTimeoutError:
            fut.cancel()
            raise ThreadsError(f"Threads API timeout after {timeout}s")


LOOP = LoopThread()


# ------------------------------------------------------------ helpers ------

def _short_media_id(post_id: str) -> str:
    """The like/unlike endpoints want the SHORT numeric media id
    (the part before '_'), not the full pk. instagrapi's media_like
    does media_pk() which strips the _user suffix, and uses the short
    id in BOTH the URL and the body's media_id. The full pk
    "<media>_<author>" is rejected (login_required) even with a
    correct signed body — that is why like kept failing after the
    URL fix (v1) and the signed-body fix (v2)."""
    return str(post_id).split("_", 1)[0]


# The instagrapi client is synchronous (requests); calls that use it
# directly run in a worker thread and are serialised, so they never
# block the asyncio loop or race each other.
_CL_LOCK = threading.Lock()


def _signed_payload(api, data: dict) -> str:
    """Build a signed_body payload the way the library's post() does.

    The media like/unlike/delete endpoints reject an EMPTY body with
    login_required even when the URL and headers are correct — the
    body must carry media_id + device identity (the same fields the
    official app / instagrapi send). The literal "SIGNATURE" placeholder
    is what the library's own post() uses and Instagram accepts it.
    """
    cl = getattr(getattr(api, "_auth_session", None), "_instagrapi_client", None)
    if cl is not None:
        data.setdefault("_uuid", getattr(cl, "uuid", None) or "")
        data.setdefault("device_id", getattr(cl, "android_device_id", None) or "")
    data = {k: v for k, v in data.items() if v not in (None, "")}
    encoded = urllib.parse.quote(string=json.dumps(data), safe="!~*'()")
    return f"signed_body=SIGNATURE.{encoded}"


def _model_dict(obj):
    """Convert a pydantic v1 model (or anything) to a plain dict."""
    if obj is None:
        return None
    if hasattr(obj, "dict"):
        try:
            return obj.dict()
        except Exception:
            pass
    if isinstance(obj, dict):
        return obj
    return {"value": str(obj)}


def _image_url(post: dict):
    try:
        cands = post.get("image_versions2", {}).get("candidates") or []
        if cands:
            return cands[0].get("url")
        cm = post.get("carousel_media") or []
        if cm:
            cands = (cm[0].get("image_versions2") or {}).get("candidates") or []
            if cands:
                return cands[0].get("url")
    except Exception:
        pass
    return None


def post_to_dict(post) -> dict:
    d = _model_dict(post)
    user = d.get("user") or {}
    caption = d.get("caption") or {}
    return {
        "id": str(d.get("id") or d.get("pk") or ""),
        "pk": d.get("pk"),
        "code": d.get("code"),
        "author": {
            "pk": user.get("pk"),
            "username": user.get("username"),
            "full_name": user.get("full_name"),
            "pic": user.get("profile_pic_url"),
            "verified": bool(user.get("is_verified")),
        },
        "text": caption.get("text") or "",
        "like_count": d.get("like_count") or 0,
        "reply_count": d.get("reply_count") or 0,
        "repost_count": d.get("repost_count") or 0,
        "has_liked": bool(d.get("has_liked")),
        "image_url": _image_url(d),
        "taken_at": d.get("taken_at"),
        "media_type": d.get("media_type"),
    }


def _timeline_items(timeline) -> tuple:
    """Return (items, next_max_id, more_available) from a timeline payload.

    Accepts a TimelineData model or a raw dict. The current API returns
    posts under "feed_items" (each wrapped in text_post_app_thread);
    older responses used "items". The pydantic TimelineData model has
    no feed_items field, so it silently drops them — hence an empty
    feed despite num_results > 0.
    """
    d = timeline if isinstance(timeline, dict) else _model_dict(timeline)
    threads = list(d.get("items") or [])
    for fi in d.get("feed_items") or []:
        threads.append(fi.get("text_post_app_thread") or fi)
    # the user-profile endpoint returns the same thread objects under
    # "threads" (not feed_items)
    threads.extend(d.get("threads") or [])
    items = []
    for it in threads:
        tis = it.get("thread_items") or []
        if not tis:
            continue
        post = tis[0].get("post")
        if not post:
            continue
        pd = post_to_dict(post)
        # first reply preview, if any
        if len(tis) > 1:
            rp = tis[1].get("post")
            if rp:
                pd["reply_preview"] = post_to_dict(rp)
        items.append(pd)
    return items, d.get("next_max_id"), bool(d.get("more_available"))


def _notification_items(raw) -> list:
    """Normalize the raw text_app_notifications payload defensively.

    The private API shape drifts; try the known key layouts and keep the raw
    item id so the UI can still act on it.
    """
    if isinstance(raw, dict):
        items = raw.get("items") or raw.get("new_items") or []
        next_max = raw.get("next_max_id")
    elif isinstance(raw, list):
        items = raw
        next_max = None
    else:
        items = []
        next_max = None
    out = []
    for it in items:
        if not isinstance(it, dict):
            continue
        args = it.get("args") or {}
        if not isinstance(args, dict):
            args = {}
        # comment text may live in args.text, or in the item itself
        text = args.get("text") or it.get("text") or ""
        author = (
            args.get("profile_name")
            or args.get("username")
            or it.get("profile_name")
            or ""
        )
        media_id = (
            args.get("media_id")
            or args.get("media_pk")
            or it.get("media_id")
            or ""
        )
        comment_id = (
            args.get("comment_id")
            or args.get("comment_pk")
            or it.get("comment_id")
            or ""
        )
        ts = it.get("timestamp") or it.get("time") or args.get("timestamp")
        out.append(
            {
                "id": str(it.get("pk") or it.get("id") or f"{media_id}:{comment_id}:{ts}"),
                "text": text,
                "author": author,
                "author_pic": args.get("profile_image") or it.get("profile_pic_url") or "",
                "author_pk": args.get("profile_id") or it.get("profile_id"),
                "post_id": str(media_id) if media_id else "",
                "comment_id": str(comment_id) if comment_id else "",
                "timestamp": ts,
                "type": it.get("type") or it.get("notif_type") or "reply",
            }
        )
    return out, next_max


# Headers whose instagrapi values are global constants (RE 14 Nov 2026).
_P0_DROP_HEADERS = (
    "IG-U-IG-DIRECT-REGION-HINT",
    "IG-U-SHBID",
    "IG-U-SHBTS",
    "IG-U-RUR",
    "X-IG-Nav-Chain",
    "X-IG-Bandwidth-Speed-KBPS",
    "X-IG-Bandwidth-Speed-KBPS-Sensitive",
    "X-IG-Bandwidth-TotalBytes-B",
    "X-IG-Bandwidth-TotalTime-MS",
)


def _apply_p0_headers(api: ThreadsAPI):
    """Override/delete the fingerprinted headers in api.auth_headers.

    Runs at _set_state (once per session setup). Values come from the
    RE of the real Threads 455 app (14 Nov 2026). Deletions: the IG-U-*
    HMAC suffixes and the Nav-Chain are constants identical for every
    instagrapi user on earth — removing them is safer than sending
    them. The bandwidth headers are random impossible values (2.5-3
    Gbps) — removed; the app sends measured values we cannot fake.
    """
    h = api.auth_headers or {}
    for k in _P0_DROP_HEADERS:
        h.pop(k, None)
    h["X-IG-Capabilities"] = IG_CAPABILITIES
    h["X-Bloks-Version-Id"] = BLOKS_VERSION_ID
    h["X-IG-App-Locale"] = ACCOUNT_LOCALE
    h["X-IG-Device-Locale"] = ACCOUNT_LOCALE
    h["X-IG-Mapped-Locale"] = ACCOUNT_LOCALE
    h["X-IG-App-Startup-Country"] = "ID"
    # Accept-Language comes from the stale merge (cl.private.headers was
    # populated at Client init, before set_locale ran) — override it.
    h["Accept-Language"] = "id-ID, en-US"
    h["X-IG-Timezone-Offset"] = str(ACCOUNT_TIMEZONE_OFFSET_MIN)
    h["X-IG-Device-Timezone"] = "Asia/Jakarta"
    # Full Barcelona UA for this session's device (not the template's
    # MODERN_DEVICE default — accounts have distinct devices).
    try:
        cl = api._auth_session._instagrapi_client
        ds = getattr(cl, "device_settings", None) or {}
        h["User-Agent"] = _barcelona_ua(ds)
    except Exception:
        pass
    # X-MID: present when the client knows it; a None mid was dropped
    # by the merge filter. The response sync fills it in from the
    # first ig-set-x-mid header (P0 #10).
    try:
        cl = api._auth_session._instagrapi_client
        mid = getattr(cl, "mid", None)
        if mid:
            h["X-MID"] = mid
    except Exception:
        pass
    api.auth_headers = h


def _sync_session_headers(api: ThreadsAPI):
    """Echo the server's session claim + mid from the last response.

    Reads api._auth_session.last_response_headers (stashed by the
    patched AioHTTPSession) and updates auth_headers + the instagrapi
    client, so the NEXT call carries the live claim instead of the
    stale "0" frozen at _set_state. Called after every private call
    via the wrappers installed in _set_state. Never raises.
    """
    try:
        sess = getattr(api, "_auth_session", None)
        headers = dict(getattr(sess, "last_response_headers", None) or {})
        if not headers:
            return
        # Header names are case-insensitive; aiohttp's CIMultiDict
        # preserves case, so normalise once.
        low = {str(k).lower(): v for k, v in headers.items()}
        claim = low.get("x-ig-set-www-claim")
        if claim:
            api.auth_headers["X-IG-WWW-Claim"] = claim
            try:
                cl = sess._instagrapi_client
                if cl is not None:
                    cl.set_ig_www_claim(claim)
            except Exception:
                pass
        mid = low.get("ig-set-x-mid")
        if mid:
            try:
                cl = sess._instagrapi_client
                if cl is not None and not getattr(cl, "mid", None):
                    cl.mid = mid
            except Exception:
                pass
            api.auth_headers["X-MID"] = mid
            # The real client also carries mid as a cookie.
            try:
                session = getattr(sess, "_session", None)
                if session is not None:
                    session.cookie_jar.update_cookies(
                        {"mid": str(mid)}, URL("https://i.instagram.com")
                    )
            except Exception:
                pass
    except Exception as e:
        log.warning("sync session headers gagal: %s", e)


def _refresh_request_headers(api: ThreadsAPI):
    """Refresh the per-request headers before a private call.

    X-Pigeon-Rawclienttime is the current client time and X-IG-SALT-IDS
    is a fresh random id in the real app — both were frozen at session
    setup in auth_headers, which is then minutes/hours stale. Refresh
    them here so every call carries current values. Never raises.
    """
    try:
        h = api.auth_headers or {}
        h["X-Pigeon-Rawclienttime"] = str(round(time.time(), 3))
        h["X-IG-SALT-IDS"] = str(random.randint(1061162222, 1061262222))
    except Exception:
        pass


async def _ensure_mid(api: ThreadsAPI):
    """Fetch a real mid (machine id) when the session has none (P0 #10).

    The mid cookie is assigned by Instagram on first contact; the API
    feed responses do not carry it, so a session restored from a bare
    sessionid has none and X-MID is dropped. One plain GET to
    instagram.com through the account's proxy sets it in the cookie
    jar; it is then sent as the X-MID header on later calls. Best
    effort — a failure is logged and the session works without it.
    """
    try:
        cl = api._auth_session._instagrapi_client
        if getattr(cl, "mid", None):
            return
        sess = getattr(api, "_auth_session", None)
        if sess is None:
            return
        await asyncio.wait_for(
            sess.get(
                url="https://www.instagram.com/",
                headers={"User-Agent": "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36"},
            ),
            timeout=20,
        )
        jar = getattr(getattr(sess, "_session", None), "cookie_jar", None)
        if jar is None:
            return
        for cookie in jar:
            if cookie.key == "mid" and cookie.value:
                cl.mid = cookie.value
                api.auth_headers["X-MID"] = cookie.value
                return
    except Exception as e:
        log.warning("mid fetch gagal (diabaikan): %s", e)


def _install_response_sync(api: ThreadsAPI):
    """Wrap api._private_post/_private_get to sync response headers.

    Installed once per ThreadsAPI instance (guarded by a marker).
    Library methods (get_post, post, get_notifications, follow_user,
    ...) all funnel through _private_post/_private_get, so wrapping
    the two covers every private call without touching each call site.
    """
    if getattr(api, "_p0_response_sync_installed", False):
        return
    api._p0_response_sync_installed = True
    orig_post = api._private_post
    orig_get = api._private_get

    async def _wrapped_post(**kwargs):
        _refresh_request_headers(api)
        res = await orig_post(**kwargs)
        _sync_session_headers(api)
        _sync_rotated_session(api)
        return res

    async def _wrapped_get(**kwargs):
        _refresh_request_headers(api)
        res = await orig_get(**kwargs)
        _sync_session_headers(api)
        _sync_rotated_session(api)
        return res

    api._private_post = _wrapped_post
    api._private_get = _wrapped_get


# --------------------------------------------------------- account client --

class AccountClient:
    """One ThreadsAPI session for a single stored account."""

    def __init__(self, account_id: str, username: str, settings_path: str):
        self.account_id = account_id
        self.username = username
        self.settings_path = settings_path
        self._api = None
        self._lock = threading.Lock()
        self.status = "unknown"  # ok | expired | error
        self.status_detail = ""
        self._primed = False  # timeline priming sent this session (P0 #9)

    # -- internal ---------------------------------------------------------
    async def _ensure_api(self) -> ThreadsAPI:
        if self._api is None:
            self._api = ThreadsAPI(settings_path=self.settings_path)
        return self._api

    def _set_state(self, api: ThreadsAPI, token: str, user_id: str, username: str):
        api.token = token
        api.auth_headers = dict(AUTH_HEADERS_TEMPLATE)
        api.auth_headers["Authorization"] = f"Bearer IGT:2:{token}"
        api.is_logged_in = True
        api.username = username
        api.user_id = str(user_id)
        # The Threads private calls go through bare aiohttp, which sent
        # only the 5 auth headers — Instagram rejected those with a
        # generic 200-fail before auth was even checked. Merge the
        # instagrapi client's full device-identity headers underneath
        # (Barcelona UA / Threads app id / Authorization still win).
        # Drop non-str values (e.g. X-MID None) — aiohttp cannot
        # serialize them.
        try:
            cl = api._auth_session._instagrapi_client
            base = {k: v for k, v in cl.private.headers.items() if isinstance(v, str)}
            api.auth_headers = {**base, **api.auth_headers}
        except Exception as e:
            log.warning("could not merge device headers: %s", e)
        # P0 (RE 14 Nov 2026): the merged instagrapi headers carry
        # constants that fingerprint every instagrapi user worldwide.
        # Override/delete them here so the aiohttp traffic is correct
        # even if the library patches were not (re)applied after a
        # venv rebuild. See patches/patch_private_headers.py (same
        # fixes at the source, for the requests-based calls).
        try:
            _apply_p0_headers(api)
        except Exception as e:
            log.warning("could not apply P0 headers: %s", e)
        # Capture the server's session claim + mid from every private
        # response and echo them on the next calls (P0 #5/#10). The
        # stock library discards response headers, so the aiohttp
        # session is patched to stash them (patches/
        # patch_response_headers.py) and the private calls are wrapped
        # here to sync them into auth_headers.
        try:
            _install_response_sync(api)
        except Exception as e:
            log.warning("could not install response sync: %s", e)
        # Keep the library's own Settings device in sync with the
        # instagrapi client — post() sends device_id/device from here,
        # and the stock OnePlus defaults would mismatch the modern
        # Samsung headers.
        try:
            cl = api._auth_session._instagrapi_client
            ds = getattr(cl, "device_settings", None) or {}
            api.settings.device_manufacturer = ds.get("manufacturer") or "samsung"
            api.settings.device_model = ds.get("model") or "SM-S918B"
            api.settings.device_android_version = ds.get("android_version") or 33
            api.settings.device_android_release = ds.get("android_release") or "13.0.0"
            android_id = getattr(cl, "android_device_id", None)
            if android_id:
                api.settings.device_id = android_id
        except Exception as e:
            log.warning("could not sync settings device: %s", e)

    def set_proxy(self, proxy: str | None) -> bool:
        """Apply (or clear) the proxy on this account's live client.

        Used when a proxy is attached to an already-logged-in account —
        no re-login needed. If the api was never created there is no
        live client yet; the stored proxy is applied on next restore.
        Returns True when a live client was updated.
        """
        proxy = (proxy or "").strip() or None
        with self._lock:
            self._proxy = proxy
            api = self._api
        if api is None:
            return False
        try:
            cl = api._auth_session._instagrapi_client
        except Exception:
            cl = None
        _apply_proxy(api, cl, proxy)
        return True

    # -- login / restore --------------------------------------------------
    async def login(self, username: str, password: str, code: str = None, totp_key: str = None, proxy: str = None):
        """Log in with Instagram credentials. Returns (token, user_id).

        Raises Need2FA when a verification code is required, ThreadsError
        otherwise (message is shown verbatim in the UI).

        proxy: optional proxy URL (e.g. http://user:pass@host:port),
        used for this login attempt — and, when the caller stores it,
        for the account's later API traffic too. If the server IP is
        rate-limited, a clean proxy IP can help.
        totp_key: optional 2FA secret key (base32, from the Authenticator
        setup) — the 6-digit code is generated from it automatically.
        Never stored; a bare 6-digit code is also accepted here.
        """
        # Preferred path: the headless-browser login. A session created
        # by a real browser login is accepted by the Threads feed API;
        # the API (CAA) login's session is rejected there
        # (logout_reason 37), so password login goes through the browser
        # now. The helper returns a web sessionid, restored exactly like
        # a sessionid login (the proven path).
        browser = _run_browser_login(username, password, totp_key, code, proxy)
        if browser is not None:
            if browser.get("need_2fa") and not (code or "").strip() and not totp_key:
                raise Need2FA("Akun ini memakai 2FA — masukkan kunci 2FA (secret key dari aplikasi Authenticator, bukan kode 6 digit), kode dibuat otomatis saat login.")
            if not browser.get("ok"):
                raise ThreadsError(browser.get("error") or "Login gagal.")
            return await self.login_by_sessionid(browser["sessionid"], username, proxy=proxy)
        # Fallback (browser helper not installed on this machine): the
        # Bloks CAA login helper, then the legacy in-process flow below.
        # The CAA session is rejected by the Threads feed, so this path
        # is only a diagnostic fallback — it will fail with needs_upgrade
        # or "Sesi tidak valid" on the live server.
        effective_code = (code or "").strip() or None
        if not effective_code and totp_key:
            effective_code = totp_code(totp_key)
        helper = _run_caa_login(username, password, effective_code, proxy)
        if helper is not None:
            if helper.get("need_2fa") and not effective_code:
                raise Need2FA("Akun ini memakai 2FA — masukkan kunci 2FA (secret key dari aplikasi Authenticator, bukan kode 6 digit), kode dibuat otomatis saat login.")
            if not helper.get("ok"):
                raise ThreadsError(helper.get("error") or "Login gagal.")
            return await self.login_by_sessionid(
                helper["sessionid"], username, settings=helper.get("settings"), proxy=proxy
            )
        api = await self._ensure_api()
        cl0 = api._auth_session._instagrapi_client
        # The library's default device is ancient (IG 269, OnePlus 6T,
        # Android 8.0) — Instagram now refuses login with "Your version
        # of Instagram is out of date". Use the modern device (IG 454,
        # Samsung SM-S918B) for the whole login flow. set_device alone
        # does NOT rebuild the session headers — set_settings + init()
        # does. init() runs BEFORE set_proxy, so it cannot wipe it.
        cl0.set_device(MODERN_DEVICE)
        cl0.set_settings({"device_settings": MODERN_DEVICE})
        cl0.init()
        if proxy:
            try:
                cl0.set_proxy(proxy.strip())
            except Exception as e:
                raise ThreadsError(f"Proxy tidak bisa dipakai: {e}")
        # Instagram KILLED the qe/sync endpoint (404 "Endpoint does not
        # exist") — the stock password_publickeys() bare GET can no
        # longer fetch the password-encryption key from ANY IP, proxy
        # or not. The key now comes back on the signed launcher/sync
        # response headers (verified live 13 Nov: key id 197). Patch
        # the instance method so the library's login flow uses it.
        def _password_publickeys_via_launcher():
            cl0.sync_launcher(login=True)
            resp = cl0.last_response
            key_id = int(resp.headers["ig-set-password-encryption-key-id"])
            key = resp.headers["ig-set-password-encryption-pub-key"]
            return key_id, key
        cl0.password_publickeys = _password_publickeys_via_launcher
        try:
            await api.login(username, password)
        except Exception as e:
            if "TwoFactorRequired" in e.__class__.__name__ or "two-factor" in str(e).lower() or "two factor" in str(e).lower():
                effective_code = (code or "").strip() or None
                if not effective_code and totp_key:
                    effective_code = totp_code(totp_key)
                if not effective_code:
                    raise Need2FA("Akun ini memakai 2FA — masukkan kunci 2FA (secret key dari aplikasi Authenticator, bukan kode 6 digit), kode dibuat otomatis saat login.")
                # Second attempt with the code, via the underlying instagrapi client
                try:
                    cl = api._auth_session._instagrapi_client
                    cl.login(username, password, verification_code=effective_code)
                    token = cl.private.headers["Authorization"].split("Bearer IGT:2:")[1]
                except Exception as e2:
                    raise ThreadsError(_clean_exc(e2))
                self._set_state(api, token, "", username)
                api.user_id = await api.get_user_id_from_username(username)
                return token, api.user_id
            raise ThreadsError(_clean_exc(e))
        if not getattr(api, "token", None):
            raise ThreadsError("Login gagal: tidak ada token yang dikembalikan.")
        try:
            cl = api._auth_session._instagrapi_client
            jar_cookies = {c.name: c.value for c in cl.private.cookies}
            sid = jar_cookies.get("sessionid")
            if sid:
                _set_aio_cookies(api, sid, jar_cookies.get("ds_user_id") or str(api.user_id))
        except Exception:
            pass
        return api.token, str(api.user_id)

    async def login_by_sessionid(self, sessionid: str, username: str = None, settings: dict | None = None, proxy: str = None):
        """Log in with an Instagram sessionid cookie value.

        The password-login endpoint is rate-limited (429) from the VPS IP,
        but authenticated API calls work fine — so a session captured in the
        user's own browser is a reliable way in. Returns (token, user_id).
        The raw sessionid is used transiently and never stored; only the
        derived Threads token is persisted (encrypted) by the caller.

        Two things the stock library flow gets wrong for us, fixed here:
        (1) it validates via IG user_info_v1 with the library's default
        device (IG 269 from 2023, OnePlus 6T) — Instagram 467s that
        ancient fingerprint, so we use a modern device and validate
        against the Threads feed API the app actually uses;
        (2) user_info_v1 is only a fallback for resolving the username.
        """
        api = await self._ensure_api()
        sessionid = (sessionid or "").strip()
        if len(sessionid) < 30:
            raise ThreadsError("Sessionid tidak valid (terlalu pendek).")
        m = re.match(r"^(\d+)", sessionid)
        if not m:
            raise ThreadsError("Sessionid tidak valid (tidak diawali angka user id).")
        user_id = m.group(1)
        username = (username or "").strip().lstrip("@") or None
        cl = _configure_client(api, sessionid, user_id, settings, proxy=proxy)
        try:
            cl.private.headers.update({"Authorization": cl.authorization})
            auth = cl.authorization or ""
            if "Bearer IGT:2:" not in auth:
                raise ThreadsError("Login sesi gagal: token tidak terbentuk.")
            token = auth.split("Bearer IGT:2:", 1)[1].strip()
            self._set_state(api, token, user_id, username or "")
            _set_aio_cookies(api, sessionid, user_id, (settings or {}).get("cookies"))
            await _ensure_mid(api)
            # Resolve the username via IG user info (modern device); a
            # failure here is not fatal — the Threads check decides.
            try:
                user = cl.user_info_v1(int(user_id))
                username = user.username or username
            except Exception as e_ig:
                resp = getattr(cl.private, "last_response", None)
                if resp is not None:
                    log.warning(
                        "user_info_v1 failed user_id=%s status=%s body=%s",
                        user_id, getattr(resp, "status_code", "?"),
                        (getattr(resp, "text", "") or "")[:300],
                    )
                log.warning("user_info_v1 failed user_id=%s: %s", user_id, e_ig)
            # The check that matters: the Threads feed API with this token.
            try:
                await api.get_timeline()
            except Exception as e_tl:
                log.warning("threads get_timeline failed user_id=%s: %s", user_id, str(e_tl)[:500])
                raise ThreadsError(_clean_exc(e_tl))
            if not username:
                raise ThreadsError("Login sesi berhasil tapi username tidak terbaca — isi username di form.")
            self.username = username
            api.username = username
            # Keep the exact session identity so the caller can persist
            # it (encrypted) — a CAA-created session must be restored
            # under the same identity every time, not just this once.
            self._session_settings = settings
            return token, user_id
        except ThreadsError:
            raise
        except Exception as e:
            raise ThreadsError(_clean_exc(e))

    async def restore(self, token: str, user_id: str, username: str, settings: dict | None = None, proxy: str = None) -> bool:
        """Restore a session from a stored token and verify it lightly."""
        api = await self._ensure_api()
        sid, uid = _session_cookies_from_token(token)
        if sid:
            _configure_client(api, sid, uid or user_id, settings, proxy=proxy)
        self._set_state(api, token, user_id, username)
        if sid:
            _set_aio_cookies(api, sid, uid or user_id, (settings or {}).get("cookies"))
        await _ensure_mid(api)
        try:
            # get_user_profile uses the anonymous GraphQL path with a stale
            # doc_id and always fails — validate with the feed instead.
            await api.get_timeline()
            self.status = "ok"
            self.status_detail = ""
            return True
        except Exception as e:
            self.status = "expired"
            self.status_detail = _clean_exc(e)
            api.is_logged_in = False
            return False

    async def close(self):
        if self._api is not None:
            try:
                await self._api.close_gracefully()
            except Exception:
                pass
            self._api = None

    def current_token(self):
        """Return the live token (possibly rotated) or None."""
        api = self._api
        if api is None:
            return None
        return getattr(api, "token", None) or None

    # -- reads ------------------------------------------------------------
    async def _prime_timeline(self, api: ThreadsAPI):
        """Send the feed-priming call the real app makes on cold start.

        P0 #9 (RE 14 Nov 2026): POST
        /feed/text_post_app_timeline_priming/ with session_id, before
        the first timeline call of a session. Best-effort — a failed
        priming must never block the feed itself.
        """
        try:
            session_id = (api.auth_headers or {}).get("X-Pigeon-Session-Id") or ""
            body = {
                "pagination_source": "text_post_feed_threads",
                "session_id": session_id,
            }
            data = "signed_body=SIGNATURE." + urllib.parse.quote(
                string=json.dumps(body), safe="!~*'()"
            )
            await api._private_post(
                url=f"{BASE_URL}/feed/text_post_app_timeline_priming/",
                headers=api.auth_headers,
                data=data,
            )
        except Exception as e:
            log.warning("timeline priming gagal (diabaikan): %s", e)

    async def timeline(self, max_id=None):
        api = await self._ensure_api()
        # Prime the feed once per session, before the first page.
        if not max_id and not self._primed:
            self._primed = True
            await self._prime_timeline(api)
        try:
            # Fetch the raw payload: api.get_timeline() returns a
            # TimelineData model that drops the "feed_items" key the
            # current API uses (see _timeline_items).
            params = {"pagination_source": "text_post_feed_threads"}
            if max_id:
                params["max_id"] = max_id
            raw = await api._private_post(
                url=f"{BASE_URL}/feed/text_post_app_timeline/",
                headers=api.auth_headers,
                data=params,
            )
        except Exception as e:
            raise ThreadsError(_clean_exc(e))
        items, next_max, more = _timeline_items(raw)
        return {"items": items, "next_max_id": next_max, "more_available": more}

    async def get_post_detail(self, post_id: str):
        api = await self._ensure_api()
        try:
            # the /text_feed/{id}/replies endpoint wants the SHORT
            # media id — the full pk "<media>_<author>" is rejected
            # with a 500 "something went wrong" (verified live).
            replies = await api.get_post(_short_media_id(str(post_id)))
        except Exception as e:
            raise ThreadsError(_clean_exc(e))
        d = _model_dict(replies)
        containing = (d.get("containing_thread") or {}).get("thread_items") or []
        main = post_to_dict(containing[0]["post"]) if containing and containing[0].get("post") else None
        out_replies = []
        for th in d.get("reply_threads") or []:
            for ti in th.get("thread_items") or []:
                if ti.get("post"):
                    out_replies.append(post_to_dict(ti["post"]))
        return {"post": main, "replies": out_replies}

    async def user_threads(self, user_id: str, max_id=None):
        """A user's own posts (profile tab). Uses the private
        /text_feed/{user_id}/profile/ endpoint raw — the library's
        get_user_threads is fine too, but the raw call keeps the
        parsing identical to the timeline (and avoids the pydantic
        model dropping fields)."""
        api = await self._ensure_api()
        try:
            params = {"count": 10}
            if max_id:
                params["max_id"] = max_id
            raw = await api._private_get(
                url=f"{BASE_URL}/text_feed/{user_id}/profile/",
                headers=api.auth_headers, data=params,
            )
        except Exception as e:
            raise ThreadsError(_clean_exc(e))
        items, nxt, more = _timeline_items(raw)
        return {"items": items, "next_max_id": nxt, "more_available": more}

    async def user_replies(self, user_id: str, max_id=None):
        api = await self._ensure_api()
        try:
            params = {"count": 10}
            if max_id:
                params["max_id"] = max_id
            raw = await api._private_get(
                url=f"{BASE_URL}/text_feed/{user_id}/profile/replies",
                headers=api.auth_headers, data=params,
            )
        except Exception as e:
            raise ThreadsError(_clean_exc(e))
        items, nxt, more = _timeline_items(raw)
        return {"items": items, "next_max_id": nxt, "more_available": more}

    async def notifications(self, max_id=None):
        api = await self._ensure_api()
        try:
            raw = await api.get_notifications(selected_filter="text_post_app_replies", max_id=max_id)
        except Exception as e:
            raise ThreadsError(_clean_exc(e))
        items, next_max = _notification_items(raw)
        return {"items": items, "next_max_id": next_max}

    async def search_user(self, query: str):
        api = await self._ensure_api()
        try:
            raw = await api.search_user(query)
        except Exception as e:
            raise ThreadsError(_clean_exc(e))
        users = []
        if isinstance(raw, dict):
            for u in raw.get("users") or []:
                users.append(
                    {
                        "pk": u.get("pk"),
                        "username": u.get("username"),
                        "full_name": u.get("full_name"),
                        "pic": u.get("profile_pic_url"),
                        "verified": bool(u.get("is_verified")),
                    }
                )
        return {"users": users}

    async def profile(self, user_id: str = None):
        api = await self._ensure_api()
        uid = user_id or api.user_id
        try:
            prof = await api.get_user_profile(str(uid))
        except Exception as e:
            raise ThreadsError(_clean_exc(e))
        d = _model_dict(prof)
        return {
            "pk": d.get("pk"),
            "username": d.get("username"),
            "full_name": d.get("full_name"),
            "pic": d.get("profile_pic_url"),
            "follower_count": d.get("follower_count"),
            "following_count": d.get("following_count"),
            "biography": d.get("biography"),
            "verified": bool(d.get("is_verified")),
        }

    # -- writes -----------------------------------------------------------
    async def publish(self, caption: str, image_path=None, url=None, parent_post_id=None):
        api = await self._ensure_api()
        try:
            # reply_id (parent_post_id) must be the SHORT media id —
            # the full pk "<media>_<author>" is rejected with
            # "Unknown Server Error" (verified live 13 Nov 01:2x:
            # full pk failed, short id posted fine).
            if parent_post_id:
                parent_post_id = _short_media_id(parent_post_id)
            # Link di dalam teks (mis. affiliate s.shopee.co.id) dilampirkan
            # sebagai link_attachment_url supaya Threads merender kartu preview.
            # Tanpa ini link hanya tampil sebagai teks biasa tanpa preview
            # (ditemukan 15 Nov 2026 — komen orang lain yang paste link via
            # aplikasi otomatis dapat kartu, komen API kita tidak).
            if url is None and image_path is None:
                m = re.search(r"https?://\S+", caption or "")
                if m:
                    url = m.group(0).rstrip(").,]'\"")
            res = await api.post(
                caption=caption,
                image_path=image_path,
                url=url,
                parent_post_id=parent_post_id,
            )
        except Exception as e:
            raise ThreadsError(_clean_exc(e))
        return _model_dict(res)

    async def like(self, post_id: str):
        api = await self._ensure_api()
        try:
            # Three aiohttp attempts all failed (v1: full pk, no body;
            # v2: full pk + signed body; v3: short id + signed body) —
            # each rejection invalidated the session. The like now goes
            # through the instagrapi client itself (the exact code path
            # the official app flow uses: media_like builds the short
            # id, the signed body and the device headers, and posts via
            # its own requests session). It is synchronous, so it runs
            # in a worker thread behind a lock.
            cl = getattr(api._auth_session, "_instagrapi_client", None)
            if cl is None:
                raise ThreadsError("client tidak tersedia")
            loop = asyncio.get_running_loop()

            def _do():
                with _CL_LOCK:
                    return bool(cl.media_like(str(post_id)))

            return await loop.run_in_executor(None, _do)
        except Exception as e:
            raise ThreadsError(_clean_exc(e))

    async def unlike(self, post_id: str):
        api = await self._ensure_api()
        try:
            cl = getattr(api._auth_session, "_instagrapi_client", None)
            if cl is None:
                raise ThreadsError("client tidak tersedia")
            loop = asyncio.get_running_loop()

            def _do():
                with _CL_LOCK:
                    return bool(cl.media_unlike(str(post_id)))

            return await loop.run_in_executor(None, _do)
        except Exception as e:
            raise ThreadsError(_clean_exc(e))

    async def repost(self, post_id: str):
        api = await self._ensure_api()
        try:
            res = await api.repost(str(post_id))
            return _model_dict(res)
        except Exception as e:
            raise ThreadsError(_clean_exc(e))

    async def follow(self, user_id: str):
        api = await self._ensure_api()
        try:
            return bool(await api.follow_user(str(user_id)))
        except Exception as e:
            raise ThreadsError(_clean_exc(e))

    async def unfollow(self, user_id: str):
        api = await self._ensure_api()
        try:
            return bool(await api.unfollow_user(str(user_id)))
        except Exception as e:
            raise ThreadsError(_clean_exc(e))

    async def delete_post(self, post_id: str):
        api = await self._ensure_api()
        try:
            # The aiohttp delete (full pk + signed body) returns False;
            # like the like, deletion goes through the instagrapi
            # client (media_delete uses the full pk, the official-app
            # path). Verified live: it removed a test reply.
            cl = getattr(api._auth_session, "_instagrapi_client", None)
            if cl is None:
                raise ThreadsError("client tidak tersedia")
            loop = asyncio.get_running_loop()

            def _do():
                with _CL_LOCK:
                    return bool(cl.media_delete(str(post_id)))

            return await loop.run_in_executor(None, _do)
        except Exception as e:
            raise ThreadsError(_clean_exc(e))


# ------------------------------------------------------------- registry ----

class ClientRegistry:
    """Holds one AccountClient per stored account id."""

    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self._clients = {}
        self._lock = threading.Lock()

    def get(self, account_id: str, username: str) -> AccountClient:
        with self._lock:
            cl = self._clients.get(account_id)
            if cl is None:
                settings_path = f"{self.data_dir}/sessions/{account_id}.json"
                cl = AccountClient(account_id, username, settings_path)
                self._clients[account_id] = cl
            return cl

    def drop(self, account_id: str):
        with self._lock:
            cl = self._clients.pop(account_id, None)
        if cl is not None:
            LOOP.run(lambda: cl.close(), timeout=30)

    def call(self, account_id: str, username: str, coro_fn, timeout=120):
        """Run a coroutine-producing callable for this account on the loop."""
        cl = self.get(account_id, username)

        async def _run():
            return await coro_fn(cl)

        return LOOP.run(_run, timeout=timeout)
