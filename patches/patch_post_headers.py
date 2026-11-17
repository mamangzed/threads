"""Patch the installed threads-api library so post() uses the merged auth
headers (device identity + modern Barcelona UA) instead of its bare
__get_app_headers() (Barcelona 289, no device headers). The bare headers
make Instagram reject the post with login_required — and the failed post
then invalidates the session, so feed/inbox start failing too.

Run with the venv Python that has threads-api installed:
    <venv>/bin/python patches/patch_post_headers.py
Idempotent: does nothing if already patched. Re-run after any
pip install / venv rebuild of threads-api.
"""
import sys
from pathlib import Path

import threads_api.src.threads_api as mod

OLD = '''        def __get_app_headers() -> dict:
            headers = {
                "User-Agent": f"Barcelona 289.0.0.77.109 Android",'''

NEW = '''        def __get_app_headers() -> dict:
            # Patched (threads-app): use the merged auth headers
            # (device identity + modern Barcelona UA) when available —
            # the bare headers here get rejected by Instagram with
            # login_required, and the failed post then invalidates
            # the session, so feed/inbox start failing too.
            if self.auth_headers:
                return dict(self.auth_headers)
            headers = {
                "User-Agent": f"Barcelona 289.0.0.77.109 Android",'''

path = Path(mod.__file__)
src = path.read_text()
if "Patched (threads-app)" in src:
    print("already patched:", path)
    sys.exit(0)
if OLD not in src:
    print("pattern not found in:", path)
    sys.exit(1)
path.write_text(src.replace(OLD, NEW, 1))
print("patched:", path)
