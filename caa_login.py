#!/usr/bin/env python3
"""Password login for Instagram via the Bloks CAA flow (instagrapi 3.x).

Why a separate process: the main app runs instagrapi 1.17.0 (Python 3.10,
pydantic v1 — the stack the feed/reply/sessionid paths are proven on).
Instagram killed the legacy accounts/login/ endpoint in Nov 2026 — it now
answers every legacy login with `needs_upgrade`, even on the latest app
version. instagrapi 3.2.11 logs in through the new Bloks CAA flow instead,
but it needs Python >= 3.11 and pydantic v2, which the main venv cannot
take. So this helper runs under its own venv (/root/ig-login/venv,
Python 3.10 + instagrapi 3.2.11 with Pillow pinned < 13) and does ONLY
the login, then hands the session back.

Protocol (stdin JSON -> stdout single JSON line, nothing else on stdout):
  in:  {"username": ..., "password": ..., "verification_code": "123456"|null,
        "proxy": "http://user:pass@host:port"|null}
  out: {"ok": true, "sessionid": "...", "user_id": "..."}
       {"ok": false, "need_2fa": true, "error": "..."}
       {"ok": false, "error": "..."}
The password is used transiently and never printed, logged or stored.
The caller restores the account from sessionid + user_id exactly like a
sessionid login (the proven path) — this helper returns no token.
"""

import json
import sys

# Threads app version (RE 14 Nov 2026, APK 455.0.0.55.72 verified
# Meta-signed). The Barcelona UA must carry the FULL device tuple —
# the short "Barcelona 454.0.0.54.77 Android" form is a shape no real
# client ever sends.
THREADS_APP_VERSION = "455.0.0.55.72"
THREADS_VERSION_CODE = "512508369"
_DEFAULT_DEVICE = {
    "android_version": 34, "android_release": "14.0.0",
    "dpi": "420dpi", "resolution": "1080x2400",
    "manufacturer": "Google", "model": "Pixel 8 Pro",
    "device": "husky", "cpu": "google",
}


def _barcelona_ua(device: dict) -> str:
    """Full Barcelona User-Agent from a device dict (RE 14 Nov 2026)."""
    d = dict(_DEFAULT_DEVICE)
    d.update(device or {})
    return (
        f"Barcelona {THREADS_APP_VERSION} Android "
        f"({d.get('android_version')}/{d.get('android_release')}; "
        f"{d.get('dpi')}; {d.get('resolution')}; {d.get('manufacturer')}; "
        f"{d.get('model')}; {d.get('device')}; {d.get('cpu')}; "
        f"id_ID; {THREADS_VERSION_CODE})"
    )


def _clean(msg: str) -> str:
    low = (msg or "").lower()
    if "twofactorrequired" in low or "two-factor" in low or "two factor" in low:
        return "Akun ini memakai 2FA — masukkan kunci 2FA."
    if "pleasewaitfewminutes" in low or "please wait a few minutes" in low:
        return ("Instagram meminta menunggu beberapa menit sebelum mencoba lagi "
                "(terlalu banyak percobaan login). Coba lagi nanti.")
    if "badpassword" in low or "bad password" in low or "invalid password" in low:
        return "Username atau password salah."
    if "badcredentials" in low or "both username and password" in low:
        return "Username atau password salah."
    if "needs_upgrade" in low or "out of date" in low:
        return "Versi aplikasi Instagram ditolak saat login. Coba lagi nanti."
    if "checkpoint" in low or "challenge" in low:
        return ("Instagram meminta verifikasi tambahan (challenge). Buka aplikasi "
                "Instagram, selesaikan verifikasinya, lalu coba login lagi.")
    if "429" in low or "too many requests" in low or "throttled" in low:
        return "Instagram membatasi permintaan (429). Tunggu beberapa menit lalu coba lagi."
    if "proxy" in low:
        return f"Proxy tidak bisa dipakai: {msg[:160]}"
    return (msg or "Login gagal.")[:300]


def _threads_feed_ok(cl) -> tuple:
    """Call the Threads feed endpoint the way the app does and report
    whether Instagram accepts this session there.

    The IG account_info call can succeed while the Threads feed rejects
    the very same session (logout_reason 37) — so a session is only
    usable if THIS check passes too. Uses the app's exact header set:
    Barcelona UA + Threads app id + Bearer token over the login
    client's device headers, through the same proxy the login used.
    Returns (ok, detail).
    """
    try:
        headers = {k: v for k, v in cl.private.headers.items() if isinstance(v, str)}
        headers["User-Agent"] = _barcelona_ua(getattr(cl, "device_settings", None) or {})
        headers["X-IG-App-ID"] = "238260118697367"
        headers["Authorization"] = cl.authorization
        headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
        r = cl.private.post(
            "https://i.instagram.com/api/v1/feed/text_post_app_timeline/",
            headers=headers,
            data={"pagination_source": "text_post_feed_threads"},
            timeout=30,
        )
        j = r.json()
        if j.get("status") == "ok" or "feed_items" in j or "items" in j:
            return True, ""
        return False, str(j)[:200]
    except Exception as e:
        return False, str(e)[:200]


def main() -> None:
    try:
        req = json.load(sys.stdin)
    except Exception:
        print(json.dumps({"ok": False, "error": "Input helper tidak valid."}))
        return
    username = (req.get("username") or "").strip()
    password = req.get("password") or ""
    code = (req.get("verification_code") or "").strip()
    proxy = (req.get("proxy") or "").strip()
    if not username or not password:
        print(json.dumps({"ok": False, "error": "Username dan password wajib diisi."}))
        return
    try:
        from instagrapi import Client
        from instagrapi.exceptions import TwoFactorRequired
    except Exception as e:
        print(json.dumps({"ok": False, "error": f"Helper login tidak siap: {e}"}))
        return
    cl = Client()
    if proxy:
        try:
            cl.set_proxy(proxy)
        except Exception as e:
            print(json.dumps({"ok": False, "error": f"Proxy tidak bisa dipakai: {e}"}))
            return
    try:
        cl.login(username, password, verification_code=code)
    except TwoFactorRequired:
        print(json.dumps({
            "ok": False, "need_2fa": True,
            "error": "Akun ini memakai 2FA — masukkan kunci 2FA.",
        }))
        return
    except Exception as e:
        print(json.dumps({"ok": False, "error": _clean(str(e) or type(e).__name__)}))
        return
    try:
        cookies = {c.name: c.value for c in cl.private.cookies}
    except Exception:
        cookies = {}
    sid = cookies.get("sessionid")
    uid = cookies.get("ds_user_id") or str(getattr(cl, "user_id", "") or "")
    if not sid or not uid:
        print(json.dumps({"ok": False, "error": "Login berhasil tapi sessionid tidak didapat."}))
        return
    # The session can be killed by Instagram the moment it is used
    # (logout_reason 37) — verify it is alive HERE, with the same
    # device and the same IP that logged in, before the app tries to
    # reuse it from a different device/IP. If it is already dead, the
    # app cannot use it either, and the caller must not retry the
    # restore step.
    try:
        cl.account_info()
        session_ok = True
        session_check = ""
    except Exception as e:
        session_ok = False
        session_check = _clean(str(e) or type(e).__name__)
    if not session_ok:
        print(json.dumps({
            "ok": False,
            "error": "Login berhasil tapi sesi langsung ditolak Instagram saat dipakai: " + session_check,
        }))
        return
    threads_ok, threads_detail = _threads_feed_ok(cl)
    if not threads_ok:
        print(json.dumps({
            "ok": False,
            "error": ("Login berhasil dan sesi IG hidup, tapi feed Threads menolak sesi ini: "
                      + threads_detail),
        }))
        return
    try:
        settings = cl.get_settings()
    except Exception:
        settings = {}
    print(json.dumps({"ok": True, "sessionid": sid, "user_id": uid, "settings": settings}))


if __name__ == "__main__":
    main()
