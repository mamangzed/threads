"""Patch threads-api's AioHTTPSession to stash the last response headers.

The stock post()/get() return only response.text() — the response
headers are discarded. Instagram sends the session claim in
X-IG-Set-WWW-Claim and the machine id in ig-set-x-mid on responses;
the real app echoes them on later calls, while our automation kept
sending the stale "0" claim frozen at login (RE 14 Nov 2026, P0 #5
and #10). This patch stores dict(response.headers) on the session as
last_response_headers after every call; threads_client.py reads it
after each private call and syncs it into auth_headers + the
instagrapi client.

Works whether or not patches/patch_aio_proxy.py was already applied
(both the proxy-patched and the pristine post/get/download forms are
recognised).

Run with the venv Python that has threads-api installed:
    <venv>/bin/python patches/patch_response_headers.py [site-packages dir]
Idempotent: does nothing if already patched. Re-run after any
pip install / venv rebuild of threads-api.
"""
import sys
from pathlib import Path

MARKER = "# patched: response-headers"

INIT_PROXY = "        self.proxy = None  # patched: aio-proxy\n"
INIT_CLIENT = "        self._instagrapi_client = Client()\n"
INIT_ADD = "        self.last_response_headers = {}  " + MARKER + "\n"

# (method, pristine body, proxy-patched body) — the stash line is added
# to whichever form is present.
METHODS = ["post", "get", "download"]


def _stash_line(method: str) -> str:
    return f"            self.last_response_headers = dict(response.headers)  {MARKER}\n"


def _patch_method(src: str, method: str) -> str:
    if method == "download":
        ret = "            return await response.read()\n"
        head = "        async with self._session.get(**kwargs) as response:\n"
    else:
        ret = "            return await response.text()\n"
        verb = "post" if method == "post" else "get"
        head = f"        async with self._session.{verb}(**kwargs) as response:\n"
    old = head + ret
    if src.count(old) != 1:
        print(f"FAILED: {method} body not found exactly once")
        sys.exit(1)
    return src.replace(old, head + _stash_line(method) + ret, 1)


def main():
    sp = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    if sp is None:
        import site
        sp = Path(site.getsitepackages()[0])
    target = sp / "threads_api" / "src" / "http_sessions" / "aiohttp_session.py"
    if not target.exists():
        print("NOT FOUND:", target)
        sys.exit(1)
    src = target.read_text()
    if MARKER in src:
        print("already patched:", target)
        return
    if INIT_PROXY in src:
        src = src.replace(INIT_PROXY, INIT_PROXY + INIT_ADD, 1)
    elif INIT_CLIENT in src:
        src = src.replace(INIT_CLIENT, INIT_CLIENT + INIT_ADD, 1)
    else:
        print("FAILED: __init__ anchor not found in", target)
        sys.exit(1)
    for method in METHODS:
        src = _patch_method(src, method)
    target.write_text(src)
    print("patched:", target)


if __name__ == "__main__":
    main()
