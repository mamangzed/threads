# threads — Automasi Threads (RE API)

Web app + client untuk automasi Threads: postingan bait, balasan affiliate,
keep-alive akun. Live di https://threads.wandalo.dev (VPS, systemd
`threads-app.service`).

Stack: Python stdlib (`ThreadingHTTPServer` + satu asyncio loop thread),
frontend vanilla JS di `public/`. Tanpa build step.

## Jalankan

```bash
python3 -m venv venv
venv/bin/pip install -r requirements.txt
WEB_PASSWORD=<password-gate> PORT=7691 venv/bin/python server.py
```

`WEB_PASSWORD` wajib diisi via env (password gate web, tidak ada default
di kode).

## Data — tidak ikut repo

- `data/master.key` — kunci enkripsi token (dibuat otomatis saat pertama jalan)
- `data/accounts.json` — daftar akun (token terenkripsi AES-256-GCM)
- `data/sessions/` — sesi per akun

## Struktur

- `server.py` — web gate + API
- `threads_client.py` — client Threads (login, feed, post, reply)
- `caa_login.py`, `caa_register.py` — login & registrasi via alur Bloks CAA
- `crypto_store.py` — enkripsi token (AES-256-GCM)
- `public/` — frontend
- `patches/` — patch library; jalankan ulang tiap venv di-rebuild
- `chrome-extension/` — ekstensi sync sessionid dari Chrome
- `products.json`, `stores.json` — katalog affiliate Shopee
- `elektronik/` — draft + foto track affiliate elektronik
