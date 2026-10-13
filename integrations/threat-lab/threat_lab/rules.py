"""Level 2 "read": deterministic reading rules over downloaded package or skill
code. Nothing is ever run, installed or extracted to disk (proposal §03.5).

Runs INSIDE the sandbox (``--network=none``, read-only files): the archive is
read member by member from memory with size caps, so a hostile archive (path
traversal, a zip bomb, a symlink) has no file system to land on.

The rules, each a plain function so a reviewer can read what fires:

* install hooks — ``package.json`` lifecycle scripts that run on install,
  a ``setup.py`` that runs commands or overrides build steps, any ``.pth``
  file (Python runs it on every start-up);
* obfuscation — a long base64-looking run, a dense run of ``\\x`` escapes, or
  ``eval``/``exec``/``Function`` fed by a decoder;
* embedded IOCs — URLs to bare IP addresses and well-known exfiltration
  endpoints (chat webhooks, bot APIs); every host and wallet address seen is
  listed for the raw record.

The report holds archive paths and hosts as found — attacker-chosen text. It is
stored as a raw artifact only; the extractor carries nothing but sha256
fingerprints and closed-vocabulary codes into the Evidence.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import tarfile
import zipfile
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Tuple

#: Caps that keep a hostile archive from exhausting the sandbox.
MAX_MEMBERS = 5000
MAX_FILE_BYTES = 2_000_000
MAX_TOTAL_BYTES = 100_000_000
MAX_LISTED_IOCS = 200

NPM_INSTALL_SCRIPTS = ("preinstall", "install", "postinstall", "prepare")
_SETUP_PY_TRIGGERS = (b"cmdclass", b"subprocess", b"os.system", b"os.popen", b"exec(", b"eval(")
_BASE64_RUN = re.compile(rb"[A-Za-z0-9+/=]{400,}")
_HEX_ESCAPES = re.compile(rb"(?:\\x[0-9a-fA-F]{2}){100,}")
_DECODED_EXECUTION = re.compile(
    rb"(eval|exec|Function)\s*\(\s*[^)]{0,200}(atob|b64decode|base64|fromCharCode|unhexlify|decode\()")
_URL_HOST = re.compile(rb"https?://([A-Za-z0-9.-]{1,253})")
_IP_URL = re.compile(rb"https?://\d{1,3}(?:\.\d{1,3}){3}\b")
_EXFIL_ENDPOINTS = re.compile(rb"discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com/services")
_EVM_ADDRESS = re.compile(rb"\b0x[0-9a-fA-F]{40}\b")


@dataclass
class ReadReport:
    """What the rules found. Paths are as written in the archive."""

    artifact_sha256: str
    files_read: int = 0
    truncated: bool = False
    install_hooks: List[Dict[str, str]] = field(default_factory=list)
    obfuscated: List[Dict[str, str]] = field(default_factory=list)
    suspicious_iocs: List[Dict[str, str]] = field(default_factory=list)
    hosts: List[str] = field(default_factory=list)
    wallets: List[str] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(self.__dict__, sort_keys=True, separators=(",", ":"))


def read_artifact(data: bytes) -> ReadReport:
    """Apply every rule to every file in *data* (a tar/tgz, a zip/wheel, or one file)."""
    report = ReadReport(artifact_sha256=hashlib.sha256(data).hexdigest())
    hosts, wallets = set(), set()
    for path, content in _members(data, report):
        report.files_read += 1
        digest = hashlib.sha256(content).hexdigest()
        hook = install_hook(path, content)
        if hook:
            report.install_hooks.append({"path": path, "sha256": digest, "hook": hook})
        if is_obfuscated(content):
            report.obfuscated.append({"path": path, "sha256": digest})
        if has_suspicious_ioc(content):
            report.suspicious_iocs.append({"path": path, "sha256": digest})
        hosts.update(match.decode("ascii").lower() for match in _URL_HOST.findall(content))
        wallets.update(match.decode("ascii").lower() for match in _EVM_ADDRESS.findall(content))
    report.hosts = sorted(hosts)[:MAX_LISTED_IOCS]
    report.wallets = sorted(wallets)[:MAX_LISTED_IOCS]
    return report


def install_hook(path: str, content: bytes) -> str:
    """The install hook *path* declares (``"npm:postinstall"``, ``"setup.py"``,
    ``"pth"``), or ``""``."""
    name = path.rsplit("/", 1)[-1]
    if name == "package.json":
        try:
            scripts = json.loads(content).get("scripts") or {}
        except (ValueError, AttributeError):
            return ""
        found = [script for script in NPM_INSTALL_SCRIPTS if isinstance(scripts, dict) and script in scripts]
        return ",".join(f"npm:{script}" for script in found)
    if name == "setup.py" and any(trigger in content for trigger in _SETUP_PY_TRIGGERS):
        return "setup.py"
    if name.endswith(".pth"):
        return "pth"
    return ""


def is_obfuscated(content: bytes) -> bool:
    return bool(_BASE64_RUN.search(content) or _HEX_ESCAPES.search(content)
                or _DECODED_EXECUTION.search(content))


def has_suspicious_ioc(content: bytes) -> bool:
    return bool(_IP_URL.search(content) or _EXFIL_ENDPOINTS.search(content))


def _members(data: bytes, report: ReadReport) -> Iterator[Tuple[str, bytes]]:
    """(path, bytes) of each regular file, never touching the disk. Over a cap
    stops the walk and sets ``report.truncated``."""
    total = 0
    for count, (path, size, read) in enumerate(_archive_entries(data)):
        if count >= MAX_MEMBERS or total + min(size, MAX_FILE_BYTES) > MAX_TOTAL_BYTES:
            report.truncated = True
            return
        content = read(MAX_FILE_BYTES)
        if size > MAX_FILE_BYTES:
            report.truncated = True
        total += len(content)
        yield path, content


def _archive_entries(data: bytes):
    if zipfile.is_zipfile(io.BytesIO(data)):
        archive = zipfile.ZipFile(io.BytesIO(data))
        for info in archive.infolist():
            if not info.is_dir():
                yield info.filename, info.file_size, lambda cap, info=info: archive.open(info).read(cap)
        return
    try:
        archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except tarfile.TarError:
        yield "artifact", len(data), lambda cap: data[:cap]
        return
    for member in archive:
        if member.isfile():
            yield member.name, member.size, lambda cap, member=member: archive.extractfile(member).read(cap)
