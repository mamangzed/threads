#!/usr/bin/env python3
"""Smoke test fitur 'Hubungkan ke Muse' — END-TO-END via HTTP.

Menjalankan server dengan DATA_DIR temp terpisah (bukan data/ live) dan
menguji:
  - GET /api/muse-prompt (tolak tanpa auth; suntik key caller sendiri;
    jangan bocorkan key user lain; cookie -> placeholder {{API_KEY}})
  - GET /extension.zip (zip berisi manifest/background/popup/ikon,
    tanpa password gate di dalamnya)
  - account_id eksplisit di POST /api/posts, POST /api/posts/{id}/reply,
    GET /api/feed (jalan + terisolasi antar user; tanpa account_id
    tetap pakai alur lama select -> aksi)
  - sync extension via API key (POST /api/accounts pakai X-API-Key)
    hanya menyentuh akun caller
  - user biasa TANPA BATAS (keputusan Sophie 17 Nov 2026): akun ke-4
    melewati batas lama 3; post/reply melewati jatah lama 10/20 tanpa
    ditolak 403 "Batas harian user"

Akun Threads di sini berupa FIXTURE (record ditulis langsung ke
accounts.json temp — server membaca file itu fresh tiap request, jadi
fixture langsung terlihat). Fixture TIDAK punya token IG valid, jadi
aksi yang sampai ke Instagram akan gagal 400 di lapisan IG — itu
diharapkan; yang diuji adalah routing + isolasi + limit (request harus
LOLOS dari 403/404 sebelum menyentuh IG).

Cara pakai:
  WEB_PASSWORD='<password gate>' python3 tests/smoke_muse_prompt.py

  Env opsional:
    THREADS_DATA_DIR  (default /tmp/muse-smoke-data)
    SMOKE_PORT        (default 7698)
    KEEP_DATA=1       (jangan hapus data temp setelah selesai)

Tidak ada password/token/API key yang di-hardcode di file ini: password
gate diambil dari env, password user dibuat acak tiap run, API key
diambil dari respons signup, sessionid hanya palsu.
"""
import io
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile
from datetime import datetime

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.environ.get("THREADS_DATA_DIR", "/tmp/muse-smoke-data")
PORT = os.environ.get("SMOKE_PORT", "7698")
BASE = f"http://127.0.0.1:{PORT}"
WEB_PASSWORD = os.environ.get("WEB_PASSWORD", "")
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


def curl_file(path, outfile, cookie_jar=None, api_key=None, timeout=60):
    """Download biner (zip) ke file. Return HTTP status."""
    cmd = ["curl", "-s", "-m", str(timeout), "-o", outfile,
           "-w", "%{http_code}", BASE + path]
    if cookie_jar:
        cmd += ["-b", cookie_jar, "-c", cookie_jar]
    if api_key:
        cmd += ["-H", f"X-API-Key: {api_key}"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
    except subprocess.TimeoutExpired:
        return 0
    try:
        return int(out.stdout.strip())
    except ValueError:
        return 0


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


def seed_accounts(user_id, names):
    """Tulis record akun fixture langsung ke accounts.json temp.

    Server membaca file ini fresh tiap request. Fixture tidak punya
    token (token_enc tidak ada) — cukup untuk routing/isolasi/limit.
    Return list id akun yang dibuat.
    """
    path = os.path.join(DATA_DIR, "accounts.json")
    try:
        with open(path, encoding="utf-8") as f:
            accounts = json.load(f)
    except Exception:
        accounts = []
    ids = []
    now = datetime.now().astimezone().isoformat()
    for i, name in enumerate(names):
        aid = "fix" + secrets.token_hex(6)
        accounts.append({
            "id": aid,
            "username": name,
            "user_id": f"1111111111{i}",
            "owner_id": user_id,
            "enc": "user",
            "active": False,
            "status": "ok",
            "status_detail": "",
            "created_at": now,
        })
        ids.append(aid)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(accounts, f)
    return ids


def seed_actions(user_id, account_id, username, n_post, n_reply):
    """Tulis entri aksi 'ok' hari ini ke actions.jsonl temp, supaya
    hitungan jatah harian user sudah melewati angka lama (10 post /
    20 balasan). ts memakai tanggal lokal mesin ini (= tanggal server).
    """
    path = os.path.join(DATA_DIR, "actions.jsonl")
    ts = datetime.now().astimezone().isoformat()
    lines = []
    for _ in range(n_post):
        lines.append({"ts": ts, "account_id": account_id, "username": username,
                      "type": "post", "target": "", "result": "ok",
                      "detail": "fixture", "owner_id": user_id})
    for _ in range(n_reply):
        lines.append({"ts": ts, "account_id": account_id, "username": username,
                      "type": "reply", "target": "", "result": "ok",
                      "detail": "fixture", "owner_id": user_id})
    with open(path, "a", encoding="utf-8") as f:
        for e in lines:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")


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
    for who in ("a", "b"):
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
        email_a = f"muse-a-{suffix}@smoke.test"
        email_b = f"muse-b-{suffix}@smoke.test"
        key_a = key_b = None
        user_a_id = user_b_id = None

        # ---- signup A + B ------------------------------------------
        for who, email, pw in (("A", email_a, pw_a), ("B", email_b, pw_b)):
            st, j, _ = curl("POST", "/api/auth/signup",
                            {"email": email, "password": pw})
            if st == 201 and j and j.get("ok") and j.get("api_key"):
                if who == "A":
                    key_a, user_a_id = j["api_key"], (j.get("user") or {}).get("id")
                else:
                    key_b, user_b_id = j["api_key"], (j.get("user") or {}).get("id")
                report(f"signup user {who}", "PASS",
                       f"201, api_key didapat (prefix {j['api_key'][:8]}...)")
            else:
                report(f"signup user {who}", "FAIL", f"status={st} body={j}")
        if not key_a or not key_b or not user_a_id or not user_b_id:
            report("setup user A/B", "FAIL", "signup tidak lengkap — tes lanjutan dilewati")
            return 1

        # ---- login A + B (cookie) -----------------------------------
        for who, email, pw in (("A", email_a, pw_a), ("B", email_b, pw_b)):
            st, j, _ = curl("POST", "/api/auth/login",
                            {"email": email, "password": pw},
                            cookie_jar=jars[who.lower()])
            report(f"login user {who}",
                   "PASS" if st == 200 and j and j.get("ok") else "FAIL",
                   f"status={st} body={j}")

        # ---- (1) /api/muse-prompt ----------------------------------
        st, j, _ = curl("GET", "/api/muse-prompt")
        report("muse-prompt tanpa auth -> 401",
               "PASS" if st == 401 else "FAIL", f"status={st} body={j}")

        st, j, _ = curl("GET", "/api/muse-prompt", api_key=key_a)
        prompt_a = (j or {}).get("prompt", "") if j else ""
        ok_prompt_a = (st == 200 and j and j.get("ok") and j.get("key_injected") is True
                       and key_a in prompt_a and key_b not in prompt_a)
        report("muse-prompt dgn key A: berisi key A, BUKAN key B",
               "PASS" if ok_prompt_a else "FAIL",
               f"status={st} key_injected={(j or {}).get('key_injected')} "
               f"len_prompt={len(prompt_a)}")
        checks = {
            "base url": "https://threads.wandalo.dev" in prompt_a,
            "header X-API-Key": "X-API-Key" in prompt_a,
            "endpoint /api/accounts": "/api/accounts" in prompt_a,
            "account_id": "account_id" in prompt_a,
            "tanpa batas": ("TANPA BATAS" in prompt_a or "tanpa batas" in prompt_a),
            "proxy per akun": "proxy" in prompt_a.lower(),
            "tanpa placeholder {{API_KEY}}": "{{API_KEY}}" not in prompt_a,
        }
        missing = [k for k, v in checks.items() if not v]
        report("muse-prompt berisi base url + endpoint + tanpa-batas + proxy",
               "PASS" if not missing else "FAIL",
               f"kurang: {missing}" if missing else "semua ada")

        st, j, _ = curl("GET", "/api/muse-prompt", api_key="tk_" + secrets.token_hex(16))
        report("muse-prompt dgn key acak -> 401",
               "PASS" if st == 401 else "FAIL", f"status={st} body={j}")

        st, j, _ = curl("GET", "/api/muse-prompt", cookie_jar=jars["a"])
        prompt_cookie = (j or {}).get("prompt", "") if j else ""
        ok_cookie = (st == 200 and j and j.get("ok")
                     and j.get("key_injected") is False
                     and "{{API_KEY}}" in prompt_cookie
                     and key_a not in prompt_cookie)
        report("muse-prompt dgn cookie: placeholder, key TIDAK bocor",
               "PASS" if ok_cookie else "FAIL",
               f"status={st} key_injected={(j or {}).get('key_injected')}")

        # ---- (2) /api/extension.zip ----------------------------------
        st, j, _ = curl("GET", "/api/extension.zip")
        report("extension.zip tanpa auth -> 401",
               "PASS" if st == 401 else "FAIL", f"status={st}")

        zip_path = os.path.join(DATA_DIR, "ext.zip")
        st = curl_file("/api/extension.zip", zip_path, cookie_jar=jars["a"])
        if st != 200 or not os.path.exists(zip_path):
            report("extension.zip terunduh (cookie A)", "FAIL", f"status={st}")
            zip_ok = False
        else:
            try:
                with zipfile.ZipFile(zip_path) as z:
                    names = z.namelist()
                    need = ["manifest.json", "background.js", "popup.js", "popup.html"]
                    missing = [n for n in need if n not in names]
                    has_icons = any(n.startswith("icons/") and n.endswith(".png") for n in names)
                    man = json.loads(z.read("manifest.json").decode("utf-8"))
                    bg = z.read("background.js").decode("utf-8", "replace")
                    pop = z.read("popup.html").decode("utf-8", "replace")
                    # Canary: kata sandi gate lama (dibangun runtime agar
                    # literalnya tidak tertulis di repo ini).
                    needle = "threads" + "123"
                    bad_secret = any(needle in z.read(n).decode("utf-8", "replace")
                                     for n in names if n.endswith((".js", ".html", ".json")))
                    no_bak = not any(".bak" in n for n in names)
                    checks = {
                        "file wajib ada": not missing,
                        "ada ikon": has_icons,
                        "tanpa file .bak": no_bak,
                        "manifest version 1.2": man.get("version") == "1.2",
                        "tanpa password gate": not bad_secret,
                        "background pakai X-API-Key": "X-API-Key" in bg,
                        "popup ada kolom apiKey": 'id="apiKey"' in pop,
                    }
                    missing_c = [k for k, v in checks.items() if not v]
                    report("extension.zip: manifest+background+popup+ikon, tanpa secret",
                           "PASS" if not missing_c else "FAIL",
                           f"isi={sorted(names)} kurang={missing_c}" if missing_c
                           else f"isi={sorted(names)}")
                    zip_ok = not missing_c
            except Exception as e:
                report("extension.zip: isi zip bisa dibaca", "FAIL", f"error: {e}")
                zip_ok = False

        # ---- (3) fixture akun A x3 + B x1 ---------------------------
        fix_a = seed_accounts(user_a_id, ["akun_fixture_a1", "akun_fixture_a2", "akun_fixture_a3"])
        fix_b = seed_accounts(user_b_id, ["akun_fixture_b1"])
        st, j, _ = curl("GET", "/api/accounts", cookie_jar=jars["a"])
        ids_a = [a.get("id") for a in (j.get("accounts") or [])] if j and j.get("ok") else None
        report("fixture: A melihat 3 akun fixture",
               "PASS" if ids_a is not None and all(x in ids_a for x in fix_a) else "FAIL",
               f"akun A={ids_a}")
        st, j, _ = curl("GET", "/api/accounts", cookie_jar=jars["b"])
        ids_b = [a.get("id") for a in (j.get("accounts") or [])] if j and j.get("ok") else None
        report("fixture: B HANYA melihat akunnya (isolasi)",
               "PASS" if ids_b == fix_b else "FAIL", f"akun B={ids_b}")

        # ---- (4) TANPA BATAS akun: akun ke-4 ------------------------
        # A sudah punya 3 fixture. Tambah ke-4 dengan sessionid palsu:
        # dulu 403 "batas akun"; sekarang harus lolos dari cek batas
        # (gagalnya di login 400 karena token palsu — wajar).
        st, j, _ = curl("POST", "/api/accounts",
                        {"sessionid": "12345678901%3Afake" + secrets.token_hex(16),
                         "username": "akun_fixture_a4"},
                        cookie_jar=jars["a"], timeout=180)
        not_limited = not (st == 403 and "batas akun" in str((j or {}).get("error", "")))
        report("tanpa batas akun: tambah akun ke-4 tidak ditolak 403 batas",
               "PASS" if not_limited else "FAIL",
               f"status={st} body={j}")

        # ---- (5) TANPA BATAS harian: seed 10 post + 20 reply -------
        # Angka lama (10 post / 20 balasan per hari) sudah terlampaui di
        # riwayat — post/reply berikutnya dulu 403 "Batas harian user",
        # sekarang harus lolos dari cek jatah (gagalnya di IG 400).
        seed_actions(user_a_id, fix_a[0], "akun_fixture_a1", n_post=10, n_reply=20)
        st, j, _ = curl("GET", "/api/history?limit=200", cookie_jar=jars["a"])
        items = (j or {}).get("items") or []
        n_fix = sum(1 for e in items
                    if e.get("detail") == "fixture" and e.get("result") == "ok")
        report("fixture aksi: 10 post + 20 reply tercatat hari ini",
               "PASS" if n_fix == 30 else "FAIL",
               f"entri fixture di riwayat={n_fix} (harap 30)")

        # ---- (6) account_id eksplisit: post / reply / feed ----------
        def _not_blocked(st, j, what):
            """Request lolos routing+limit (bukan 403/404). Gagal di IG
            (400, token fixture tidak valid) adalah hasil yang diharapkan."""
            err = str((j or {}).get("error", ""))
            if st == 403 or st == 404:
                return False, f"status={st} body={j}"
            if "Batas harian user" in err or "bukan akun Anda" in err:
                return False, f"status={st} body={j}"
            return True, f"status={st} (lolos routing+limit, gagal di IG: {err[:100]})"

        st, j, _ = curl("POST", "/api/posts",
                        {"text": "tes prompt muse", "account_id": fix_a[0]},
                        api_key=key_a, timeout=180)
        ok, det = _not_blocked(st, j, "post")
        report("post dgn account_id milik sendiri (lewati jatah lama)",
               "PASS" if ok else "FAIL", det)

        st, j, _ = curl("POST", "/api/posts",
                        {"text": "tes prompt muse", "account_id": fix_b[0]},
                        api_key=key_a, timeout=60)
        report("post dgn account_id user lain -> 403",
               "PASS" if st == 403 and "bukan akun Anda" in str((j or {}).get("error", "")) else "FAIL",
               f"status={st} body={j}")

        fake_post = "1234567890123456789_12345678901"
        st, j, _ = curl("POST", f"/api/posts/{fake_post}/reply",
                        {"text": "tes balasan", "account_id": fix_a[0]},
                        api_key=key_a, timeout=180)
        ok, det = _not_blocked(st, j, "reply")
        report("reply dgn account_id milik sendiri (lewati jatah lama)",
               "PASS" if ok else "FAIL", det)

        st, j, _ = curl("POST", f"/api/posts/{fake_post}/reply",
                        {"text": "tes balasan", "account_id": fix_b[0]},
                        api_key=key_a, timeout=60)
        report("reply dgn account_id user lain -> 403",
               "PASS" if st == 403 and "bukan akun Anda" in str((j or {}).get("error", "")) else "FAIL",
               f"status={st} body={j}")

        st, j, _ = curl("GET", f"/api/feed?account_id={fix_a[0]}",
                        api_key=key_a, timeout=120)
        ok, det = _not_blocked(st, j, "feed")
        report("feed dgn account_id milik sendiri",
               "PASS" if ok else "FAIL", det)

        st, j, _ = curl("GET", f"/api/feed?account_id={fix_b[0]}",
                        api_key=key_a, timeout=60)
        report("feed dgn account_id user lain -> 403",
               "PASS" if st == 403 and "bukan akun Anda" in str((j or {}).get("error", "")) else "FAIL",
               f"status={st} body={j}")

        st, j, _ = curl("GET", "/api/feed?account_id=ghost" + secrets.token_hex(6),
                        api_key=key_a, timeout=60)
        report("feed dgn account_id tidak ada -> 404",
               "PASS" if st == 404 else "FAIL", f"status={st} body={j}")

        # ---- (7) kompatibilitas alur lama (tanpa account_id) --------
        st, j, _ = curl("POST", "/api/posts",
                        {"text": "tes kompat legacy"},
                        cookie_jar=jars["a"], timeout=180)
        ok, det = _not_blocked(st, j, "post legacy")
        report("post TANPA account_id tetap jalan (alur lama)",
               "PASS" if ok else "FAIL", det)

        # ---- (8) sync extension via API key -------------------------
        # POST /api/accounts pakai X-API-Key (jalur yang dipakai
        # extension bila kolom API key diisi).
        st, j, _ = curl("POST", "/api/accounts",
                        {"sessionid": "12345678901%3Afake" + secrets.token_hex(16),
                         "username": "akun_fixture_b1"},
                        api_key=key_a, timeout=180)
        report("sync extension: username milik B ditolak 403 (A pakai key A)",
               "PASS" if st == 403 and "bukan akun Anda" in str((j or {}).get("error", "")) else "FAIL",
               f"status={st} body={j}")

        st, j, _ = curl("POST", "/api/accounts",
                        {"sessionid": "12345678901%3Afake" + secrets.token_hex(16),
                         "username": "akun_fixture_a1"},
                        api_key=key_a, timeout=180)
        ok_sync = not (st in (401, 403))
        report("sync extension: username milik sendiri lolos auth (gagal di login 400, wajar)",
               "PASS" if ok_sync else "FAIL",
               f"status={st} body={j}")

        st, j, _ = curl("POST", "/api/accounts",
                        {"sessionid": "12345678901%3Afake" + secrets.token_hex(16)},
                        api_key=key_a, timeout=180)
        report("sync extension: tanpa username, key A diterima (bukan 401)",
               "PASS" if st != 401 else "FAIL", f"status={st} body={j}")

        st, j, _ = curl("GET", "/api/accounts", cookie_jar=jars["b"])
        ids_b2 = [a.get("id") for a in (j.get("accounts") or [])] if j and j.get("ok") else None
        report("sync extension: akun B tidak berubah",
               "PASS" if ids_b2 == fix_b else "FAIL", f"akun B={ids_b2}")

        # Catatan jujur: sync yang SUKSES (akun benar-benar dibuat /
        # token di-refresh) tidak bisa dibuktikan tanpa token IG valid —
        # yang dibuktikan di atas adalah auth + isolasi jalurnya.
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
