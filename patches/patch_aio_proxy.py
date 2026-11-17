"""Patch threads-api's AioHTTPSession to support a default proxy.

The stock AioHTTPSession creates a bare aiohttp.ClientSession and its
post/get pass **kwargs straight through — there is no way to set a
proxy for all calls. This patch adds a `proxy` attribute (default
None) and injects it into every request when set, so the app can route
a whole account's Threads API traffic through a residential proxy
(e.g. DataImpulse, city-locked) instead of the VPS datacenter IP.

Idempotent: safe to run again; skips an already-patched file.
Run with the venv python after every threads-api reinstall:
    <venv>/bin/python patches/patch_aio_proxy.py [site-packages dir]
"""
import sys
from pathlib import Path

MARKER = "# patched: aio-proxy"

OLD_INIT = """    def __init__(self):
        self._session = aiohttp.ClientSession()
        self._instagrapi_client = Client()
"""
NEW_INIT = """    def __init__(self):
        self._session = aiohttp.ClientSession()
        self._instagrapi_client = Client()
        self.proxy = None  """ + MARKER + """
"""

HELPER = '''
    def _with_proxy(self, kwargs):
        """Inject the default proxy into a request's kwargs (if set)."""
        if getattr(self, "proxy", None) and "proxy" not in kwargs:
            kwargs["proxy"] = self.proxy
        return kwargs
'''

OLD_DOWNLOAD = """    async def download(self, **kwargs):
        async with self._session.get(**kwargs) as response:
            return await response.read()
"""
NEW_DOWNLOAD = """    async def download(self, **kwargs):
        kwargs = self._with_proxy(kwargs)
        async with self._session.get(**kwargs) as response:
            return await response.read()
"""

OLD_POST = """    async def post(self, **kwargs):
        async with self._session.post(**kwargs) as response:
            return await response.text()
"""
NEW_POST = """    async def post(self, **kwargs):
        kwargs = self._with_proxy(kwargs)
        async with self._session.post(**kwargs) as response:
            return await response.text()
"""

OLD_GET = """    async def get(self, **kwargs):
        async with self._session.get(**kwargs) as response:
            return await response.text()
"""
NEW_GET = """    async def get(self, **kwargs):
        kwargs = self._with_proxy(kwargs)
        async with self._session.get(**kwargs) as response:
            return await response.text()
"""


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
    for old, new in [
        (OLD_INIT, NEW_INIT),
        (OLD_DOWNLOAD, NEW_DOWNLOAD),
        (OLD_POST, NEW_POST),
        (OLD_GET, NEW_GET),
    ]:
        if src.count(old) != 1:
            print("FAILED: pattern not found exactly once in", target)
            print(repr(old[:80]))
            sys.exit(1)
        src = src.replace(old, new)
    # Insert the helper right after __init__'s closing (before start()).
    anchor = "    async def start(self):"
    if src.count(anchor) != 1:
        print("FAILED: anchor not found:", anchor)
        sys.exit(1)
    src = src.replace(anchor, HELPER.lstrip("\n") + "\n" + anchor, 1)
    target.write_text(src)
    print("patched:", target)


if __name__ == "__main__":
    main()
