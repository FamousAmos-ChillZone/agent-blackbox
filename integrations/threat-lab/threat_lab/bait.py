"""The inert bait a level-4 microVM carries (proposal §03.5 ground rules, F-014).

Bait is the ONLY data ever placed where a sample can take it: credentials
valid nowhere and a wallet with zero funds. Every value is fixed, public (it
is in this file) and carries the marker ``TLBAIT`` or derives from the
published seed below, so it can never be mistaken for a real secret and it is
easy to spot on the wire.

The guest (:mod:`threat_lab.guest`) plants :data:`BAIT_FILES` in the test
user's home and :data:`BAIT_ENVIRONMENT` in its environment; the host
(:mod:`threat_lab.traffic`) looks for :func:`bait_markers` in the recorded
traffic. Seeing one proves the bait was sent. Not seeing one proves nothing
(TLS hides payloads), so the lab only ever reports "seen", never "not sent".

Copied into the guest image; imports nothing from this package.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Dict, Tuple

#: A public seed: the bait wallet's key is derived from it, so anyone can see it holds nothing.
_WALLET_SEED = b"threat-lab inert bait wallet - zero funds - valid nowhere"

AWS_ACCESS_KEY_ID = "AKIATLBAIT00INERT000"
AWS_SECRET_ACCESS_KEY = "TLBAITinertSecretKeyValidNowhere00000000"
NPM_TOKEN = "npm" + "_" + "TLBAITinertTokenValidNowhere00000000"   # assembled at runtime: no secret-shaped literal in source (LES-022)
GITHUB_TOKEN = "ghp" + "_" + "TLBAITinertTokenValidNowhere00000000"   # assembled at runtime: no secret-shaped literal in source (LES-022)
WALLET_PRIVATE_KEY = "0x" + hashlib.sha256(_WALLET_SEED).hexdigest()

#: Home-relative path → content, planted before the sample runs.
BAIT_FILES: dict[str, str] = {
    ".aws/credentials": (f"[default]\naws_access_key_id = {AWS_ACCESS_KEY_ID}\n"
                         f"aws_secret_access_key = {AWS_SECRET_ACCESS_KEY}\n"),
    ".npmrc": f"//registry.npmjs.org/:_authToken={NPM_TOKEN}\n",
    ".config/gh/hosts.yml": f"github.com:\n    oauth_token: {GITHUB_TOKEN}\n    user: tlbait\n",
    ".ethereum/keystore.txt": f"{WALLET_PRIVATE_KEY}\n",
}

#: Environment variables set for the sample.
BAIT_ENVIRONMENT: dict[str, str] = {
    "AWS_ACCESS_KEY_ID": AWS_ACCESS_KEY_ID,
    "AWS_SECRET_ACCESS_KEY": AWS_SECRET_ACCESS_KEY,
    "NPM_TOKEN": NPM_TOKEN,
    "GITHUB_TOKEN": GITHUB_TOKEN,
    "PRIVATE_KEY": WALLET_PRIVATE_KEY,
}

_SECRETS = (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, NPM_TOKEN, GITHUB_TOKEN, WALLET_PRIVATE_KEY[2:])


def bait_markers() -> tuple[bytes, ...]:
    """Byte strings whose presence in outbound traffic means bait was sent:
    each secret as written, and each secret base64-encoded on its own (a
    secret encoded in the middle of a larger blob is not found: "seen" stays
    a yes-only answer)."""
    plain = tuple(secret.encode("ascii") for secret in _SECRETS)
    return plain + tuple(base64.b64encode(secret) for secret in plain)
