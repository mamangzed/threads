#!/usr/bin/env python3
"""Smoke test multi-user Threads app — END-TO-END via HTTP.

Menjalankan server dengan DATA_DIR temp terpisah (bukan data/ live) dan
menguji signup/login, isolasi antar user, API key, admin, batas akun,
dan logout.

Cara pakai:
  WEB_PASSWORD='<password gate>' python3 tests/smoke_multiuser.py

  Env opsional:
    THREADS_DATA_DIR  (default /tmp/mu-smoke-data)
    SMOKE_PORT        (default 7699)
    KEEP_DATA=1       (jangan hapus data temp setelah selesai)

Tidak ada password/token/API key yang di-hardcode di file ini: password
gate diambil dari env, password user dibuat acak tiap run, API key
diambil dari respons signup.
"""
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
import urllib.request
import urllib.error

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.environ.get("THREADS_DATA_DIR", "/tmp/mu-smoke-data")
PORT = os.environ.get("SMOKE_PORT", "7699")
BASE = f"http://127.0.0.1:{PORT}"
WEB_PASSWORD = os.environ.get("WEB_PASSWORD", "")
# Server butuh dependensi (cryptography, instagrapi, threads-api) yang
# ada di threads-venv, bukan di python3 sistem. Bisa di-override:
#   SMOKE_PYTHON=/path/ke/python python3 tests/smoke_multiuser.py
_VENV_PY = os.path.expanduser("~/workspace/tools/threads-venv/bin/python")
PYTHON = os.environ.get("SMOKE_PYTHON") or (_VENV_PY if os.path.exists(_VENV_PY) else "python3")

RESULTS = []  # (name, status, detail)  status: PASS / FAIL / SKIP


def report(name, status, detail=""):
    RESULTS.append((name, status, detail))
    print(f"[{status}] {name}" + (f" — {detail}" if detail else ""), flush=True)


def curl(method, path, body=None, cookie_jar=None, api_key=None, timeout=30):
    """Satu panggilan HTTP via curl. Return (status, json_or_None, raw)."""
    cmd = ["curl", "-s", "-m", str(timeout), "-w", "\n%{http_code}",
           "-X", method, BASE + path]
    if cookie_jar:
        cmd += ["-b", cookie_jar, "-c", cookie_jar]
    headers = ["Content-Type: application/json"]
    if api_key:
        headers.append(f"X-API-Key: {api_key}")
    for h in headers:
        cmd += ["-H", h]
    if body is not None:
        cmd += ["-d", json.dumps(body)]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
    except subprocess.TimeoutExpired:
        return 0, None, "curl timeout"
    raw = out.stdout
    if "\n" in raw:
        payload, code = raw.rsplit("\n", 1)
    else:
        payload, code = raw, ""
    try:
        status = int(code.strip())
    except ValueError:
        status = 0
    try:
        parsed = json.loads(payload) if payload.strip() else None
    except json.JSONDecodeError:
        parsed = None
    return status, parsed, payload[:300]


def wait_health(proc, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with urllib.request.urlopen(BASE + "/api/health", timeout=3) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(1)
    return False


def main():
    if not WEB_PASSWORD:
        print("ERROR: env WEB_PASSWORD wajib diisi saat menjalankan tes.", file=sys.stderr)
        return 2
    live_data = os.path.realpath(os.path.join(REPO, "data"))
    if os.path.realpath(DATA_DIR) == live_data:
        print(f"ERROR: THREADS_DATA_DIR menunjuk data/ live ({live_data}) — batal.", file=sys.stderr)
        return 2

    shutil.rmtree(DATA_DIR, ignore_errors=True)
    os.makedirs(DATA_DIR, exist_ok=True)
    jars = {}
    for who in ("a", "b", "admin"):
        jars[who] = os.path.join(DATA_DIR, f"jar-{who}.txt")

    env = dict(os.environ)
    env.update({"PORT": PORT, "THREADS_DATA_DIR": DATA_DIR,
                "WEB_PASSWORD": WEB_PASSWORD})
    proc = subprocess.Popen(
        [PYTHON, "server.py"], cwd=REPO, env=env,
        stdout=open(os.path.join(DATA_DIR, "server.log"), "wb"),
        stderr=subprocess.STDOUT)
    keep_data = os.environ.get("KEEP_DATA") == "1"
    try:
        if not wait_health(proc):
            report("server start", "FAIL",
                   f"server tidak sehat dalam 60 dtk — log di {DATA_DIR}/server.log")
            keep_data = True
            return 1
        report("server start", "PASS", f"port {PORT}, data {DATA_DIR}")

        suffix = secrets.token_hex(4)
        pw_a = "Sm0ke-" + secrets.token_urlsafe(12)
        pw_b = "Sm0ke-" + secrets.token_urlsafe(12)
        email_a = f"smoke-a-{suffix}@smoke.test"
        email_b = f"smoke-b-{suffix}@smoke.test"
        key_a = key_b = None
        user_a = user_b = None
        acct_a_id = None

        # ---- (a) signup A + B -------------------------------------
        for who, email, pw in (("A", email_a, pw_a), ("B", email_b, pw_b)):
            st, j, _ = curl("POST", "/api/auth/signup",
                            {"email": email, "password": pw})
            if st == 201 and j and j.get("ok") and j.get("api_key"):
                if who == "A":
                    key_a, user_a = j["api_key"], j.get("user", {})
                else:
                    key_b, user_b = j["api_key"], j.get("user", {})
                report(f"signup user {who}", "PASS", f"201, api_key didapat (prefix {j['api_key'][:6]}...)")
            else:
                report(f"signup user {who}", "FAIL", f"status={st} body={j}")

        # ---- (b) login A + B, /api/auth/me ------------------------
        for who, email, pw in (("A", email_a, pw_a), ("B", email_b, pw_b)):
            st, j, _ = curl("POST", "/api/auth/login",
                            {"email": email, "password": pw},
                            cookie_jar=jars[who.lower()])
            if not (st == 200 and j and j.get("ok")):
                report(f"login user {who}", "FAIL", f"status={st} body={j}")
                continue
            report(f"login user {who}", "PASS", f"email={email}")
            st2, j2, _ = curl("GET", "/api/auth/me", cookie_jar=jars[who.lower()])
            if st2 == 200 and j2 and j2.get("ok") and j2.get("user", {}).get("email") == email:
                report(f"/api/auth/me user {who}", "PASS",
                       f"user={j2['user'].get('email')} limits={j2['user'].get('limits')}")
            else:
                report(f"/api/auth/me user {who}", "FAIL", f"status={st2} body={j2}")

        # ---- (c) A tambah akun Threads (sessionid palsu) -----------
        fake_sid = "12345678901%3Afake" + secrets.token_hex(16)
        st, j, raw = curl("POST", "/api/accounts",
                          {"sessionid": fake_sid, "username": "akun_palsu_smoke"},
                          cookie_jar=jars["a"], timeout=180)
        if st >= 500:
            report("tambah akun sessionid palsu (A)", "FAIL",
                   f"status={st} (server error, harusnya 4xx rapi) body={j or raw}")
        elif j and j.get("ok"):
            acct_a_id = (j.get("account") or {}).get("id")
            report("tambah akun sessionid palsu (A)", "PASS",
                   f"status={st} — backend menerima akun tanpa token valid (id={acct_a_id}); "
                   "isolasi di bawah memakai akun ini")
        elif st >= 400 and j and j.get("ok") is False:
            report("tambah akun sessionid palsu (A)", "PASS",
                   f"status={st} gagal rapi: {str(j.get('error'))[:120]}")
        else:
            report("tambah akun sessionid palsu (A)", "FAIL",
                   f"status={st} respons tak terduga: {j or raw}")

        # ---- (d) isolasi: B tidak melihat / tidak bisa pakai akun A --
        # Catatan kontrak AKTUAL (server.py, sejak 17 Nov 2026): reply/
        # post MENERIMA account_id eksplisit di body — routing lewat akun
        # itu bila milik caller (403 bila milik user lain). Tanpa
        # account_id, routing lewat akun aktif milik caller sendiri
        # (_active_client). Yang diuji di sini: reply B gagal tanpa
        # menyentuh akun A (400 "belum ada akun" bila B tak punya akun);
        # isolasi account_id diuji di smoke_muse_prompt.py.
        if acct_a_id:
            st, j, _ = curl("GET", "/api/accounts", cookie_jar=jars["b"])
            ids_b = [a.get("id") for a in (j.get("accounts") or [])] if j and j.get("ok") else None
            if ids_b is not None and acct_a_id not in ids_b:
                report("isolasi GET /api/accounts (B)", "PASS",
                       f"B melihat {len(ids_b)} akun, akun A tidak ada")
            else:
                report("isolasi GET /api/accounts (B)", "FAIL",
                       f"status={st} akun B={ids_b} (akun A={acct_a_id})")

            st, j, _ = curl("POST", f"/api/accounts/{acct_a_id}/select",
                            {}, cookie_jar=jars["b"])
            report("isolasi select akun A oleh B", "PASS" if st == 403 else "FAIL",
                   f"status={st} body={j}")

            st, j, _ = curl("DELETE", f"/api/accounts/{acct_a_id}",
                            cookie_jar=jars["b"])
            report("isolasi delete akun A oleh B", "PASS" if st == 403 else "FAIL",
                   f"status={st} body={j}")

            st, j, _ = curl("POST", "/api/posts/0000000000000000000/reply",
                            {"text": "tes isolasi"},
                            cookie_jar=jars["b"])
            # B tak punya akun -> routing menolak sebelum menyentuh akun A.
            ok_reply = st == 400 and j and "belum ada akun" in str(j.get("error", ""))
            report("isolasi reply B (tidak bisa pakai akun A)",
                   "PASS" if ok_reply else "FAIL",
                   f"status={st} body={j}")
        else:
            # Tanpa akun A yang berhasil dibuat, uji negatif: B mencoba
            # select/delete id acak harus 404 (bukan 200/500), dan
            # GET /api/accounts B harus kosong.
            ghost = "ghost" + secrets.token_hex(6)
            st, j, _ = curl("POST", f"/api/accounts/{ghost}/select",
                            {}, cookie_jar=jars["b"])
            report("isolasi select id acak oleh B -> 404",
                   "PASS" if st == 404 else "FAIL", f"status={st} body={j}")
            st, j, _ = curl("DELETE", f"/api/accounts/{ghost}",
                            cookie_jar=jars["b"])
            report("isolasi delete id acak oleh B -> 404",
                   "PASS" if st == 404 else "FAIL", f"status={st} body={j}")
            st, j, _ = curl("GET", "/api/accounts", cookie_jar=jars["b"])
            ids_b = [a.get("id") for a in (j.get("accounts") or [])] if j and j.get("ok") else None
            report("isolasi GET /api/accounts (B) kosong",
                   "PASS" if ids_b == [] else "FAIL",
                   f"status={st} akun={ids_b}")
            report("isolasi select/delete akun A oleh B", "SKIP",
                   "tidak ada akun A (tambah akun gagal rapi di (c)) — "
                   "uji 403 antar-user butuh token IG valid")
            st, j, _ = curl("POST", "/api/posts/0000000000000000000/reply",
                            {"text": "tes isolasi"},
                            cookie_jar=jars["b"])
            ok_reply = st == 400 and j and "belum ada akun" in str(j.get("error", ""))
            report("isolasi reply B (tidak bisa pakai akun A)",
                   "PASS" if ok_reply else "FAIL",
                   f"status={st} body={j}")

        # ---- (e) API key -------------------------------------------
        if key_a:
            st, j, _ = curl("GET", "/api/accounts", api_key=key_a)
            ok_a = st == 200 and j and j.get("ok")
            report("GET /api/accounts dgn X-API-Key A", "PASS" if ok_a else "FAIL",
                   f"status={st} body={j}")
            if ok_a and acct_a_id:
                ids = [a.get("id") for a in (j.get("accounts") or [])]
                report("API key A melihat akun A", "PASS" if acct_a_id in ids else "FAIL",
                       f"akun di list: {ids}")
            if key_b:
                st, j, _ = curl("GET", "/api/accounts", api_key=key_b)
                ids_b = [a.get("id") for a in (j.get("accounts") or [])] if j and j.get("ok") else None
                if st == 200 and ids_b is not None and acct_a_id not in (ids_b or []):
                    report("X-API-Key B tidak melihat akun A", "PASS",
                           f"B melihat {len(ids_b)} akun")
                else:
                    report("X-API-Key B tidak melihat akun A", "FAIL",
                           f"status={st} akun={ids_b}")
            st, j, _ = curl("GET", "/api/accounts", api_key="tk_" + secrets.token_hex(16))
            report("X-API-Key acak ditolak 401", "PASS" if st == 401 else "FAIL",
                   f"status={st} body={j}")
        else:
            report("API key", "SKIP", "signup gagal — tidak ada key A untuk diuji")

        # ---- (f) admin: list users, disable B, enable lagi ---------
        st, j, _ = curl("POST", "/api/login", {"password": WEB_PASSWORD},
                        cookie_jar=jars["admin"])
        if not (st == 200 and j and j.get("ok")):
            report("login gate admin", "FAIL", f"status={st} body={j}")
        else:
            report("login gate admin", "PASS")
            st, j, _ = curl("GET", "/api/admin/users", cookie_jar=jars["admin"])
            users = (j.get("users") or []) if j and j.get("ok") else None
            emails = [u.get("email") for u in users] if users is not None else None
            if users is not None and email_a in emails and email_b in emails:
                report("admin GET /api/admin/users", "PASS",
                       f"melihat A dan B ({len(users)} user)")
            else:
                report("admin GET /api/admin/users", "FAIL",
                       f"status={st} users={emails}")
            b_id = None
            if users:
                for u in users:
                    if u.get("email") == email_b:
                        b_id = u.get("id")
            if b_id:
                st, j, _ = curl("POST", f"/api/admin/users/{b_id}/disable",
                                {}, cookie_jar=jars["admin"])
                if st == 200 and j and j.get("ok"):
                    report("admin disable B", "PASS")
                    st2, j2, _ = curl("POST", "/api/auth/login",
                                      {"email": email_b, "password": pw_b},
                                      cookie_jar=jars["b"])
                    report("login B ditolak saat disabled",
                           "PASS" if st2 in (401, 403) else "FAIL",
                           f"status={st2} body={j2}")
                    st3, j3, _ = curl("GET", "/api/accounts", api_key=key_b)
                    report("key B ditolak saat disabled",
                           "PASS" if st3 in (401, 403) else "FAIL",
                           f"status={st3} body={j3}")
                    st4, j4, _ = curl("POST", f"/api/admin/users/{b_id}/enable",
                                      {}, cookie_jar=jars["admin"])
                    if st4 == 200 and j4 and j4.get("ok"):
                        report("admin enable B lagi", "PASS")
                        st5, j5, _ = curl("POST", "/api/auth/login",
                                          {"email": email_b, "password": pw_b},
                                          cookie_jar=jars["b"])
                        report("login B berhasil lagi setelah enable",
                               "PASS" if st5 == 200 and j5 and j5.get("ok") else "FAIL",
                               f"status={st5} body={j5}")
                    else:
                        report("admin enable B lagi", "FAIL", f"status={st4} body={j4}")
                else:
                    report("admin disable B", "FAIL", f"status={st} body={j}")
            else:
                report("admin disable/enable B", "SKIP", "id user B tidak ditemukan di /api/admin/users")

        # ---- (g) tanpa batas akun (keputusan Sophie 17 Nov 2026) -----
        # User biasa TANPA BATAS jumlah akun: tambah akun ke-4 (dan
        # seterusnya) TIDAK BOLEH ditolak 403 "batas akun". Dengan token
        # palsu, tambah akun gagal di login (400) — itu wajar; yang
        # diuji di sini: tidak ada penolakan 403 batas. Bukti penuh
        # (akun ke-4 melewati batas lama 3, dengan akun fixture) ada di
        # smoke_muse_prompt.py.
        if acct_a_id:
            verdict = None
            for i in range(2, 5):
                st, j, _ = curl("POST", "/api/accounts",
                                {"sessionid": "12345678901%3Afake" + secrets.token_hex(16),
                                 "username": f"akun_palsu_smoke_{i}"},
                                cookie_jar=jars["a"], timeout=180)
                if st == 403 and j and "batas akun" in str(j.get("error", "")):
                    report("tanpa batas akun (tambah ke-4 tidak ditolak 403)",
                           "FAIL", f"403 batas di percobaan ke-{i}: {j}")
                    verdict = "fail"
                    break
                if (j and j.get("ok")) or st == 400:
                    continue  # sukses / gagal di login (token palsu) = bukan batas
                report("tanpa batas akun (tambah ke-4 tidak ditolak 403)",
                       "SKIP", f"tambah akun ke-{i} respons tak terduga (status={st}, {j})")
                verdict = "skip"
                break
            if verdict is None:
                report("tanpa batas akun (tambah ke-4 tidak ditolak 403)",
                       "PASS", "3 percobaan tambah, tidak ada 403 batas")
        else:
            report("tanpa batas akun (tambah ke-4 tidak ditolak 403)", "SKIP",
                   "tambah akun butuh token valid — lihat smoke_muse_prompt.py untuk bukti fixture")

        # ---- (h) logout -> /api/auth/me 401 ------------------------
        st, j, _ = curl("POST", "/api/auth/logout", {}, cookie_jar=jars["a"])
        st2, j2, _ = curl("GET", "/api/auth/me", cookie_jar=jars["a"])
        report("logout -> /api/auth/me 401",
               "PASS" if st2 == 401 else "FAIL",
               f"logout status={st}, me status={st2} body={j2}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.environ.get("KEEP_DATA") != "1" and not keep_data:
            shutil.rmtree(DATA_DIR, ignore_errors=True)

    fails = [r for r in RESULTS if r[1] == "FAIL"]
    skips = [r for r in RESULTS if r[1] == "SKIP"]
    print(f"\nRingkasan: {len(RESULTS)} kasus, "
          f"{len(RESULTS) - len(fails) - len(skips)} PASS, "
          f"{len(fails)} FAIL, {len(skips)} SKIP")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
