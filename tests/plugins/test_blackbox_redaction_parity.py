"""Cross-runtime redaction parity (LES-021, KI-179).

The hermes plugin (`kernel/redaction.py`) and the OpenClaw bridge
(`integrations/openclaw/src/redact.ts`) each carry ONE redactor with the same
rule table. This test builds secret-shaped inputs AT RUNTIME (no secret-shaped
literal in the repo, LES-022), runs them through both runtimes and fails on any
byte of difference. The TypeScript half is `integrations/openclaw/test/redaction-parity.mjs`.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from plugins.blackbox.kernel import redaction

REPO = Path(__file__).resolve().parents[2]
TSX = REPO / "node_modules" / ".bin" / "tsx"
SCRIPT = REPO / "integrations" / "openclaw" / "test" / "redaction-parity.mjs"

# Filler built at runtime: recognizable shapes, never real material.
_BODY = "FAKEKEYMATERIAL" * 4
_ALNUM = "abcdefghijklmnopqrstuvwxyz0123456789"
_HEX = ("0123456789abcdef" * 4)[::-1]                    # 64 hex, built at runtime


def _pem(label: str, cut_off: bool = False) -> str:
    begin = "-----BEGIN " + label + " KEY-----"
    end = "-----END " + label + " KEY-----"
    return begin + "\n" + _BODY + ("" if cut_off else "\n" + end)


_WORDS = (REPO / "plugins" / "blackbox" / "kernel" / "crypto_secrets" / "bip39_english.txt").read_text(encoding="ascii").split()


def _phrase(count: int, start: int = 7, separator: str = " ") -> str:
    """List words picked at runtime (checksum not needed: redaction is by run)."""
    return separator.join(_WORDS[(start + 97 * i) % len(_WORDS)] for i in range(count))


def _cases() -> list[str]:
    private = "PRIVATE"
    numbered = " ".join(f"{i + 1}. {word}" for i, word in enumerate(_phrase(12).split()))
    return [
        "seed: " + _phrase(12) + " done",
        "srp " + _phrase(24, separator=",\n") + "!",
        numbered,
        "elevenish " + _phrase(11) + " qzx",                         # too short: stays
        _phrase(6) + " notaword " + _phrase(6),                     # broken run: stays
        "Café " + _phrase(12) + " 😀 " + _phrase(13, start=99),      # non-ASCII around runs
        "word " * 3 + "the " + _phrase(12, start=3) + " and AKIA" + "ABCDEFGHIJKLMNOP",
        "PRIVATE" + "_KEY=0x" + _HEX + " and " + '{"privateKey": "' + _HEX + '"}',
        "PK=" + _HEX + " txHash: 0x" + _HEX + " apk_sha256: " + _HEX,          # only the labelled one goes
        f"before {_pem('RSA ' + private)} after",
        f"x{_pem(private, cut_off=True)}",
        "aws " + "AKIA" + "ABCDEFGHIJKLMNOP" + " in args",
        "anthropic " + "sk-" + "ant-" + _ALNUM[:24],
        "openai " + "sk-" + "proj-" + _ALNUM[:24] + " and " + "sk-" + _ALNUM[:20],
        "short " + "sk-" + _ALNUM[:17],
        "github " + "ghp_" + _ALNUM[:24] + " " + "github_pat" + "_" + _ALNUM[:18],
        "slack " + "xoxb-" + "123456789012" + "-" + _ALNUM[:12],
        "google " + "AIza" + ("Z" * 35) + " end",
        "stripe " + "sk_live_" + _ALNUM[:22],
        '{"type": "service_account", "project_id": "x"}',
        "jwt " + "eyJ" + _ALNUM[:10] + ".eyJ" + _ALNUM[:10] + "." + _ALNUM[:12],
        "Authorization: Bearer " + _ALNUM[:30] + " then text",
        "DB_PASSWORD=" + "hunter2secret" + " API_KEY: " + _ALNUM[:12],
        '{"api_key": "' + _ALNUM[:16] + '", "note": "short"}',
        "the password policy requires 12 characters",     # prose about secrets stays
        "token=" + "abc",                                   # too short to be a value
        "mixed " + "sk-" + _ALNUM[:20] + " Bearer " + _ALNUM[:8] + " PRIVATE_KEY=" + _ALNUM[:9],
        "",
    ]


@pytest.mark.skipif(not TSX.exists() or shutil.which("node") is None, reason="tsx/node not installed")
def test_both_runtimes_redact_identically(tmp_path):
    cases = _cases()
    case_file = tmp_path / "cases.json"
    case_file.write_text(json.dumps(cases), encoding="utf-8")
    result = subprocess.run([str(TSX), str(SCRIPT), str(case_file)], capture_output=True, text=True, timeout=120,
                            cwd=str(REPO), check=True)
    from_typescript = json.loads(result.stdout)
    from_python = [redaction.redact_secret_values(text) for text in cases]
    assert from_typescript == from_python
    # And the pass did something: every secret-shaped input lost its material.
    for text, out in zip(cases, from_python):
        assert _BODY not in out and "hunter2secret" not in out
        if text and text not in (cases[-4], cases[-3], cases[3], cases[4]):
            assert "[REDACTED" in out, text
    assert from_python[3] == cases[3] and from_python[4] == cases[4]


def test_both_runtimes_ship_the_same_pinned_wordlist():
    python_copy = REPO / "plugins" / "blackbox" / "kernel" / "crypto_secrets" / "bip39_english.txt"
    bridge_copy = REPO / "integrations" / "openclaw" / "src" / "bip39-english.txt"
    assert python_copy.read_bytes() == bridge_copy.read_bytes()
