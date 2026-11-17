"""Patch instagrapi's base_headers so the client stops sending the
global-constant fingerprints the RE of the real Threads 455 app found
(14 Nov 2026, ~/workspace/reverse/threads-app/README.md).

What it changes in instagrapi/mixins/private.py (base_headers):
  - X-IG-Capabilities: 3brTvx0= -> 3brTv10C (real app value)
  - X-IG-Nav-Chain: REMOVED (hardcoded constant, identical for every
    instagrapi user worldwide; the real app builds it from navigation)
  - IG-U-IG-DIRECT-REGION-HINT / IG-U-SHBID / IG-U-SHBTS / IG-U-RUR:
    REMOVED (constant HMAC suffixes, identical for every instagrapi
    user worldwide; IG-U-DS-USER-ID is kept — it is just the user id)
  - X-IG-Bandwidth-*: REMOVED (random impossible values, 2.5-3 Gbps;
    the app sends measured values we cannot fake)
  - X-Pigeon-Session-Id: stable per Client instance (was a fresh UUID
    on every base_headers access, i.e. every request)
And in instagrapi/mixins/auth.py:
  - bloks_versioning_id default: ce555e55... -> 8f5ec0ab... (real app)

The same values are also enforced in threads_client.py (_set_state /
_apply_p0_headers) so the aiohttp traffic stays correct even if this
patch is forgotten after a venv rebuild — this patch fixes the
requests-based calls (user_info_v1, media_delete, ...) too.

Run with the venv Python that has instagrapi installed:
    <venv>/bin/python patches/patch_private_headers.py [site-packages dir]
Idempotent: does nothing if already patched. Re-run after any
pip install / venv rebuild of instagrapi.
"""
import sys
from pathlib import Path

MARKER = "# patched: private-headers"

PRIVATE_REPLACEMENTS = [
    # Capabilities
    (
        '"X-IG-Capabilities": "3brTvx0=",  # "3brTvwE=" in instabot',
        '"X-IG-Capabilities": "3brTv10C",  # patched: private-headers (real Threads 455 value)',
    ),
    # Nav-Chain: remove the whole line
    (
        '            "X-IG-Nav-Chain": "9MV:self_profile:2,ProfileMediaTabFragment:self_profile:3,9Xf:self_following:4",\n',
        '',
    ),
    # IG-U-* constant HMAC suffixes: remove all four lines
    (
        '                    "IG-U-IG-DIRECT-REGION-HINT": f"LLA,{self.user_id},{next_year}:01f7bae7d8b131877d8e0ae1493252280d72f6d0d554447cb1dc9049b6b2c507c08605b7",\n',
        '',
    ),
    (
        '                    "IG-U-SHBID": f"12695,{self.user_id},{next_year}:01f778d9c9f7546cf3722578fbf9b85143cd6e5132723e5c93f40f55ca0459c8ef8a0d9f",\n',
        '',
    ),
    (
        '                    "IG-U-SHBTS": f"{int(time.time())},{self.user_id},{next_year}:01f7ace11925d0388080078d0282b75b8059844855da27e23c90a362270fddfb3fae7e28",\n',
        '',
    ),
    (
        '                    "IG-U-RUR": f"RVA,{self.user_id},{next_year}:01f7f627f9ae4ce2874b2e04463efdb184340968b1b006fa88cb4cc69a942a04201e544c",\n',
        '',
    ),
    # Bandwidth: remove all three random-value lines
    (
        '''            "X-IG-Bandwidth-Speed-KBPS": str(
                random.randint(2500000, 3000000) / 1000
            ),  # "-1.000"
''',
        '',
    ),
    (
        '''            "X-IG-Bandwidth-TotalBytes-B": str(
                random.randint(5000000, 90000000)
            ),  # "0"
''',
        '',
    ),
    (
        '            "X-IG-Bandwidth-TotalTime-MS": str(random.randint(2000, 9000)),  # "0"\n',
        '',
    ),
    # Pigeon session id: stable per Client instance
    (
        '"X-Pigeon-Session-Id": self.generate_uuid("UFS-", "-1"),',
        '"X-Pigeon-Session-Id": getattr(self, "_pigeon_sid", None) or self.__dict__.setdefault("_pigeon_sid", self.generate_uuid("UFS-", "-1")),  # patched: private-headers (stable per session)',
    ),
]

AUTH_REPLACEMENTS = [
    (
        'self.bloks_versioning_id = "ce555e5500576acd8e84a66018f54a05720f2dce29f0bb5a1f97f0c10d6fac48"',
        'self.bloks_versioning_id = "8f5ec0abc5f3dbbd823773bbd39ae9703d2a92f63e9189c89ee878de00fb866a"  # patched: private-headers (real Threads 455 value)',
    ),
]


def _patch_file(path: Path, replacements) -> bool:
    src = path.read_text()
    if MARKER in src:
        print("already patched:", path)
        return False
    for old, new in replacements:
        if src.count(old) != 1:
            print("FAILED: pattern not found exactly once in", path)
            print(repr(old[:100]))
            sys.exit(1)
        src = src.replace(old, new)
    path.write_text(src)
    print("patched:", path)
    return True


def main():
    sp = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    if sp is None:
        import site
        sp = Path(site.getsitepackages()[0])
    private = sp / "instagrapi" / "mixins" / "private.py"
    auth = sp / "instagrapi" / "mixins" / "auth.py"
    for target in (private, auth):
        if not target.exists():
            print("NOT FOUND:", target)
            sys.exit(1)
    _patch_file(private, PRIVATE_REPLACEMENTS)
    _patch_file(auth, AUTH_REPLACEMENTS)


if __name__ == "__main__":
    main()
