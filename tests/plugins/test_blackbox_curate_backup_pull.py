"""Curator-state backup (trust-and-threat-lab I2, proposal §03.1, F-037/F-052).

``scripts/blackbox-curate-backup-pull.sh`` pulls each node's curate home over
SSH into an archive encrypted on the Mac; ``…-restore.sh`` restores one into an
empty curate home. These tests drive both scripts end to end with a fake
``ssh`` on PATH that runs the remote command against a temporary "node" home,
so the real pipeline (remote tar → CMS AES-256-GCM → decrypt → extract) runs
without a network. Data reaches the scripts through the environment or their
own flags, never as extra interpreter words (LES-037); the parse test runs
under bash 5 because macOS bash 3.2 passing proves nothing for Linux (LES-038).
"""

from __future__ import annotations

import hashlib
import os
import plistlib
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "scripts"
PULL = SCRIPTS / "blackbox-curate-backup-pull.sh"
RESTORE = SCRIPTS / "blackbox-curate-backup-restore.sh"
PLIST_TEMPLATE = SCRIPTS / "blackbox-curate-backup.plist.template"

PASSPHRASE = "correct-horse-battery-staple-7731"
PLAINTEXT_MARKER = "provenance-id-4f1c-plaintext-marker"
READ_ONLY_COMMAND = re.compile(r"^tar -C \S+ -czf - curate$")
# The interpreter the scripts run under, as launchd runs them; point it at a
# bash 5 to exercise the behaviour (not only the parse) under bash 5.
SCRIPT_BASH = os.environ.get("BLACKBOX_TEST_BASH", "/bin/bash")

# The curate home of a curator node, one file per kind of state §03.1 names.
NODE_CURATE_FILES = {
    "provenance.jsonl": f'{{"id": "{PLAINTEXT_MARKER}", "subject": "urn:report:1"}}\n',
    "proposals/prop-0001.json": '{"state": "pending"}\n',
    "budget.json": '{"spent_usd": 1.25}\n',
    "consent.jsonl": '{"policy_hash": "abc"}\n',
    "keepalive.json": "{}\n",
    "signing_log.jsonl": '{"signed": "manifest-3"}\n',
    "publish_ledger.jsonl": '{"batch": 7}\n',
    "lab/jobs/job-1.json": '{"level": 2}\n',
    "sources/osv/cache.json": '{"GHSA-x": "clean"}\n',
    ".alarms_seen.json": "[]\n",
}


# ---------------------------------------------------------------------------
# Toolchain lookup
# ---------------------------------------------------------------------------

def _bash5() -> str | None:
    """A bash ≥ 5 from $BLACKBOX_TEST_BASH5, PATH, or Homebrew; None if absent."""
    candidates = [os.environ.get("BLACKBOX_TEST_BASH5"), shutil.which("bash"),
                  "/opt/homebrew/bin/bash", "/usr/local/bin/bash", "/usr/bin/bash", "/bin/bash"]
    for candidate in candidates:
        if not candidate or not Path(candidate).is_file():
            continue
        probe = subprocess.run([candidate, "-c", 'echo "${BASH_VERSINFO[0]}"'],
                               capture_output=True, text=True, check=False)
        if probe.returncode == 0 and probe.stdout.strip().isdigit() and int(probe.stdout) >= 5:
            return candidate
    return None


def _openssl3_dir() -> str | None:
    openssl = shutil.which("openssl")
    for candidate in [openssl, "/opt/homebrew/bin/openssl", "/usr/local/bin/openssl"]:
        if candidate and Path(candidate).is_file():
            version = subprocess.run([candidate, "version"], capture_output=True, text=True, check=False).stdout
            if version.startswith("OpenSSL 3"):
                return str(Path(candidate).parent)
    return None


OPENSSL3_DIR = _openssl3_dir()
needs_openssl3 = pytest.mark.skipif(
    OPENSSL3_DIR is None or shutil.which("bash") is None,
    reason="needs bash and OpenSSL 3 (CMS AES-256-GCM); macOS LibreSSL cannot do it")


# ---------------------------------------------------------------------------
# Fixture: a node, a Mac, a backup key pair kept outside every curate home
# ---------------------------------------------------------------------------

def _tree_snapshot(root: Path, *, with_mtime: bool = False) -> dict[str, tuple]:
    """relative path → (kind, sha256, mode[, mtime]) for every entry under root."""
    snapshot: dict[str, tuple] = {}
    for path in sorted(root.rglob("*")):
        stat = path.lstat()
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else ""
        entry = ("file" if path.is_file() else "dir", digest, stat.st_mode & 0o7777)
        snapshot[str(path.relative_to(root))] = entry + ((stat.st_mtime_ns,) if with_mtime else ())
    return snapshot


class Bench:
    """Paths and environment for one run of the backup scripts."""

    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path
        self.node_home = tmp_path / "node_home"
        self.node_curate = self.node_home / ".hermes" / "blackbox" / "curate"
        self.mac_home = tmp_path / "mac_home"
        self.mac_curate = self.mac_home / ".hermes" / "blackbox" / "curate"
        self.backup_dir = tmp_path / "mac_home" / "BlackboxCurateBackups"
        self.keys = tmp_path / "usb_stick"
        self.private_key = self.keys / "backup-key.pem"
        self.recipient = self.mac_home / "backup-recipient.pem"
        self.nodes_file = self.mac_home / "curate-nodes.txt"
        self.ssh_log = tmp_path / "ssh.log"
        self.stubs = tmp_path / "stubs"

        for relative, text in NODE_CURATE_FILES.items():
            target = self.node_curate / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        (self.node_curate / "lab" / "empty-queue").mkdir()
        (self.node_curate / "sources" / "blob.bin").write_bytes(bytes(range(256)) * 64)
        os.chmod(self.node_curate / "consent.jsonl", 0o600)
        self.mac_curate.mkdir(parents=True)
        self.keys.mkdir()
        self.nodes_file.write_text("# name ssh-target [curate path]\nnode-a admin@node-a\n")
        self._make_keys()
        self._make_fake_ssh()

    def _make_keys(self) -> None:
        subprocess.run(
            [str(Path(OPENSSL3_DIR) / "openssl"), "req", "-x509", "-newkey", "rsa:2048",
             "-days", "30", "-subj", "/CN=blackbox-curate-backup-test",
             "-keyout", str(self.private_key), "-out", str(self.recipient),
             "-passout", "env:BACKUP_TEST_PASSPHRASE"],
            check=True, capture_output=True, env={**os.environ, "BACKUP_TEST_PASSPHRASE": PASSPHRASE})

    def _make_fake_ssh(self) -> None:
        """`ssh [opts] target command` → log the argv, run command as the node user."""
        self.stubs.mkdir()
        stub = self.stubs / "ssh"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            'printf "%s\\n" "$*" >> "$FAKE_SSH_LOG"\n'
            'command="${@: -1}"\n'
            'cd "$FAKE_NODE_HOME" && HOME="$FAKE_NODE_HOME" exec /bin/sh -c "$command"\n')
        stub.chmod(0o755)

    def env(self, **extra: str) -> dict[str, str]:
        return {
            "PATH": f"{self.stubs}:{OPENSSL3_DIR}:/usr/bin:/bin",
            "HOME": str(self.mac_home),
            "BLACKBOX_BACKUP_NODES": str(self.nodes_file),
            "BLACKBOX_BACKUP_RECIPIENT": str(self.recipient),
            "BLACKBOX_BACKUP_DIR": str(self.backup_dir),
            "FAKE_SSH_LOG": str(self.ssh_log),
            "FAKE_NODE_HOME": str(self.node_home),
            **extra,
        }

    def pull(self, *args: str, **extra_env: str) -> subprocess.CompletedProcess:
        return subprocess.run([SCRIPT_BASH, str(PULL), *args], capture_output=True, text=True,
                              env=self.env(**extra_env), cwd=self.tmp, check=False)

    def restore(self, archive: Path, target: Path, key: Path | None = None,
                **extra_env: str) -> subprocess.CompletedProcess:
        extra_env.setdefault("BLACKBOX_RESTORE_PASSIN", "env:BACKUP_TEST_PASSPHRASE")
        return subprocess.run(
            [SCRIPT_BASH, str(RESTORE), "--archive", str(archive),
             "--key", str(key or self.private_key), "--target", str(target)],
            capture_output=True, text=True, cwd=self.tmp,
            env=self.env(BACKUP_TEST_PASSPHRASE=PASSPHRASE, **extra_env), check=False)

    def archives(self, node: str = "node-a") -> list[Path]:
        return sorted((self.backup_dir / node).glob(f"{node}-*.tar.gz.cms"))

    def ssh_calls(self) -> list[str]:
        return self.ssh_log.read_text().splitlines() if self.ssh_log.exists() else []


@pytest.fixture
def bench(tmp_path: Path) -> Bench:
    return Bench(tmp_path)


def _is_inside(child: Path, parent: Path) -> bool:
    return child.resolve().is_relative_to(parent.resolve())


def _encrypt_to_recipient(bench: Bench, plain: Path) -> Path:
    """Encrypt a hand-built tar.gz the way the pull script does (CMS AES-256-GCM)."""
    encrypted = plain.with_suffix(plain.suffix + ".cms")
    subprocess.run([str(Path(OPENSSL3_DIR) / "openssl"), "cms", "-encrypt", "-binary",
                    "-aes-256-gcm", "-outform", "DER", "-recip", str(bench.recipient),
                    "-in", str(plain), "-out", str(encrypted)], check=True, capture_output=True)
    return encrypted


# ---------------------------------------------------------------------------
# Parse checks (LES-037/038)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("script", [PULL, RESTORE], ids=lambda path: path.name)
def test_script_parses_under_bash_5(script: Path) -> None:
    bash5 = _bash5()
    if bash5 is None:
        pytest.skip("no bash >= 5 here (macOS ships 3.2); set BLACKBOX_TEST_BASH5 or run in Linux CI")
    result = subprocess.run([bash5, "-n", str(script)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("script", [PULL, RESTORE], ids=lambda path: path.name)
def test_script_parses_under_the_system_bash(script: Path) -> None:
    if not Path("/bin/bash").is_file():
        pytest.skip("no /bin/bash")
    result = subprocess.run(["/bin/bash", "-n", str(script)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("script", [PULL, RESTORE], ids=lambda path: path.name)
def test_script_avoids_bash_version_sensitive_constructs(script: Path) -> None:
    """LES-038: patsub with a replacement, mapfile and associative arrays differ 3.2 → 5."""
    text = "\n".join(line for line in script.read_text().splitlines()
                     if not line.lstrip().startswith("#"))
    assert not re.search(r"\$\{\w+//", text)
    assert "mapfile" not in text and "readarray" not in text and "declare -A" not in text


# ---------------------------------------------------------------------------
# Criterion 1: restore into an empty curate home reproduces every file
# ---------------------------------------------------------------------------

@needs_openssl3
def test_pull_then_restore_into_an_empty_curate_home_reproduces_every_file(bench: Bench) -> None:
    original = _tree_snapshot(bench.node_curate)

    pulled = bench.pull()
    assert pulled.returncode == 0, pulled.stderr + pulled.stdout
    [archive] = bench.archives()
    assert PLAINTEXT_MARKER.encode() not in archive.read_bytes(), "archive must be encrypted at rest"
    assert archive.stat().st_mode & 0o077 == 0, "archive readable by other users"

    target = bench.tmp / "restored_home" / "curate"  # absent: the restore creates it
    restored = bench.restore(archive, target)
    assert restored.returncode == 0, restored.stderr + restored.stdout
    assert _tree_snapshot(target) == original

    empty_target = bench.tmp / "second_home" / "curate"
    empty_target.mkdir(parents=True)  # an existing EMPTY directory is accepted too
    assert bench.restore(archive, empty_target).returncode == 0
    assert _tree_snapshot(empty_target) == original


@needs_openssl3
def test_the_archive_key_lives_outside_every_curate_home(bench: Bench) -> None:
    """The keys this bench (like the documented setup) uses sit outside the curate homes…"""
    for key in (bench.recipient, bench.private_key):
        assert not _is_inside(key, bench.mac_curate)
        assert not _is_inside(key, bench.node_curate)


@needs_openssl3
def test_pull_refuses_a_key_inside_the_curate_home(bench: Bench) -> None:
    """…and the scripts refuse to run with one inside."""
    inside = bench.mac_curate / "backup-recipient.pem"
    shutil.copy(bench.recipient, inside)
    result = bench.pull(BLACKBOX_BACKUP_RECIPIENT=str(inside))
    assert result.returncode == 2
    assert "outside the curate home" in result.stderr
    assert bench.ssh_calls() == [] and not bench.backup_dir.exists()


@needs_openssl3
def test_pull_refuses_a_recipient_kept_beside_the_archives(bench: Bench) -> None:
    """A key next to the archives travels with them on every copy of the folder."""
    bench.backup_dir.mkdir(parents=True)
    beside = bench.backup_dir / "backup-recipient.pem"
    shutil.copy(bench.recipient, beside)
    result = bench.pull(BLACKBOX_BACKUP_RECIPIENT=str(beside))
    assert result.returncode == 2 and "beside the archives" in result.stderr
    assert bench.ssh_calls() == [] and bench.archives() == []


@needs_openssl3
def test_pull_honours_blackbox_home_when_locating_the_curate_home(bench: Bench) -> None:
    custom_home = bench.tmp / "custom_blackbox"
    (custom_home / "curate").mkdir(parents=True)
    inside = custom_home / "curate" / "recipient.pem"
    shutil.copy(bench.recipient, inside)
    result = bench.pull(BLACKBOX_BACKUP_RECIPIENT=str(inside), BLACKBOX_HOME=str(custom_home))
    assert result.returncode == 2 and "outside the curate home" in result.stderr


@needs_openssl3
def test_restore_refuses_a_key_inside_the_curate_home_or_the_target(bench: Bench) -> None:
    assert bench.pull().returncode == 0
    [archive] = bench.archives()

    in_mac_home = bench.mac_curate / "backup-key.pem"
    shutil.copy(bench.private_key, in_mac_home)
    target = bench.tmp / "restored" / "curate"
    result = bench.restore(archive, target, key=in_mac_home)
    assert result.returncode == 2 and "outside the curate home" in result.stderr

    target.mkdir(parents=True)
    in_target = target / "backup-key.pem"
    shutil.copy(bench.private_key, in_target)
    result = bench.restore(archive, target, key=in_target)
    assert result.returncode == 2
    assert "not empty" in result.stderr or "outside the target" in result.stderr, result.stderr


# ---------------------------------------------------------------------------
# Criterion 2: no key printed or stored; the node side is read-only
# ---------------------------------------------------------------------------

@needs_openssl3
def test_dry_run_connects_to_nothing_and_shows_only_a_read_command(bench: Bench) -> None:
    bench.nodes_file.write_text("node-a admin@node-a\nnode-b admin@node-b /srv/bb/curate\n")
    result = bench.pull("--dry-run")
    assert result.returncode == 0, result.stderr
    assert bench.ssh_calls() == [], "a dry run must not connect"
    assert not bench.backup_dir.exists()
    commands = re.findall(r"would run on \S+ \(read-only\): (.+)", result.stdout)
    assert commands == ["tar -C ~/.hermes/blackbox -czf - curate", "tar -C /srv/bb -czf - curate"]
    assert all(READ_ONLY_COMMAND.match(command) for command in commands)


@needs_openssl3
def test_a_real_pull_runs_one_read_only_command_and_changes_nothing_on_the_node(bench: Bench) -> None:
    before = _tree_snapshot(bench.node_home, with_mtime=True)
    assert bench.pull().returncode == 0
    assert _tree_snapshot(bench.node_home, with_mtime=True) == before

    [call] = bench.ssh_calls()
    assert "BatchMode=yes" in call and "ForwardAgent=no" in call
    remote_command = call.rsplit("admin@node-a ", 1)[1]
    assert READ_ONLY_COMMAND.match(remote_command), remote_command


@needs_openssl3
def test_neither_script_prints_or_stores_the_key_or_its_passphrase(bench: Bench) -> None:
    pulled = bench.pull()
    [archive] = bench.archives()
    restored = bench.restore(archive, bench.tmp / "restored" / "curate")
    assert pulled.returncode == 0 and restored.returncode == 0

    key_body = "".join(bench.private_key.read_text().splitlines()[1:-1])[:64]
    output = pulled.stdout + pulled.stderr + restored.stdout + restored.stderr
    assert PASSPHRASE not in output and key_body not in output
    for written_root in (bench.backup_dir, bench.tmp / "restored", bench.mac_curate):
        for path in written_root.rglob("*"):
            if path.is_file():
                content = path.read_bytes()
                assert PASSPHRASE.encode() not in content, path
                assert b"PRIVATE KEY" not in content, path
    assert not list(bench.tmp.glob("restored/.curate-restore.*")), "decrypted temp left behind"


@needs_openssl3
def test_pull_refuses_a_recipient_file_that_holds_a_private_key(bench: Bench) -> None:
    bundle = bench.mac_home / "bundle.pem"
    bundle.write_text(bench.private_key.read_text() + bench.recipient.read_text())
    result = bench.pull(BLACKBOX_BACKUP_RECIPIENT=str(bundle))
    assert result.returncode == 2 and "private key" in result.stderr
    assert bench.ssh_calls() == []


@needs_openssl3
def test_restore_refuses_a_literal_passphrase_on_the_command_line(bench: Bench) -> None:
    assert bench.pull().returncode == 0
    [archive] = bench.archives()
    result = bench.restore(archive, bench.tmp / "r" / "curate",
                           BLACKBOX_RESTORE_PASSIN=f"pass:{PASSPHRASE}")
    assert result.returncode == 2
    assert PASSPHRASE not in result.stdout + result.stderr


# ---------------------------------------------------------------------------
# Failure handling: nothing half-written, nothing merged, nothing escapes
# ---------------------------------------------------------------------------

@needs_openssl3
def test_a_node_whose_curate_home_is_missing_fails_without_an_archive(bench: Bench) -> None:
    bench.nodes_file.write_text("node-a admin@node-a\nnode-b admin@node-b /nowhere/curate\n")
    result = bench.pull()
    assert result.returncode == 1
    assert "node-b: FAILED" in result.stderr
    assert len(bench.archives("node-a")) == 1
    assert not list((bench.backup_dir / "node-b").glob("*")), "no partial archive may remain"


@pytest.mark.parametrize("line", [
    "node-a admin@node-a;reboot",
    "node-a -oProxyCommand=evil",
    "node-a admin@node-a ~/../../etc/curate",
    "node-a admin@node-a ~/.hermes/blackbox/curate;rm",
    "node-a admin@node-a /srv/not-a-curate-home",
    "bad/name admin@node-a",
])
@needs_openssl3
def test_a_bad_node_line_is_refused_before_any_connection(bench: Bench, line: str) -> None:
    bench.nodes_file.write_text(line + "\n")
    result = bench.pull()
    assert result.returncode == 2, result.stdout
    assert bench.ssh_calls() == []


@needs_openssl3
def test_restore_refuses_a_target_that_is_not_empty(bench: Bench) -> None:
    assert bench.pull().returncode == 0
    [archive] = bench.archives()
    target = bench.tmp / "live" / "curate"
    target.mkdir(parents=True)
    (target / "provenance.jsonl").write_text("live state\n")
    result = bench.restore(archive, target)
    assert result.returncode == 2 and "not empty" in result.stderr
    assert (target / "provenance.jsonl").read_text() == "live state\n"


@needs_openssl3
def test_a_tampered_archive_restores_nothing(bench: Bench) -> None:
    assert bench.pull().returncode == 0
    [archive] = bench.archives()
    data = bytearray(archive.read_bytes())
    data[len(data) // 2] ^= 0x01
    archive.write_bytes(bytes(data))
    target = bench.tmp / "restored" / "curate"
    result = bench.restore(archive, target)
    assert result.returncode == 1
    assert not target.exists()


@needs_openssl3
def test_restore_refuses_members_outside_curate(bench: Bench) -> None:
    crafted = bench.tmp / "crafted.tar.gz"
    payload = bench.tmp / "payload.txt"
    payload.write_text("escaped\n")
    with tarfile.open(crafted, "w:gz") as archive:
        archive.add(payload, arcname="curate/../../escaped.txt")
    target = bench.tmp / "restored" / "curate"
    result = bench.restore(_encrypt_to_recipient(bench, crafted), target)
    assert result.returncode == 1
    assert "archive member with '..'" in result.stderr, result.stderr  # the script's check, not tar's
    assert not target.exists() and not (bench.tmp / "escaped.txt").exists()


@needs_openssl3
def test_restore_refuses_a_member_outside_curate_without_dots(bench: Bench) -> None:
    crafted = bench.tmp / "crafted.tar.gz"
    payload = bench.tmp / "payload.txt"
    payload.write_text("stray\n")
    with tarfile.open(crafted, "w:gz") as archive:
        archive.add(payload, arcname="curate/provenance.jsonl")
        archive.add(payload, arcname="other/stray.txt")
    target = bench.tmp / "restored" / "curate"
    result = bench.restore(_encrypt_to_recipient(bench, crafted), target)
    assert result.returncode == 1 and "outside curate/" in result.stderr, result.stderr
    assert not target.exists()


@needs_openssl3
def test_restore_refuses_an_archive_holding_a_link(bench: Bench) -> None:
    """A curate home has no links; one in an archive could point extraction anywhere."""
    crafted = bench.tmp / "crafted.tar.gz"
    payload = bench.tmp / "payload.txt"
    payload.write_text("ok\n")
    with tarfile.open(crafted, "w:gz") as archive:
        archive.add(payload, arcname="curate/provenance.jsonl")
        link = tarfile.TarInfo("curate/sources")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../../etc"
        archive.addfile(link)
    target = bench.tmp / "restored" / "curate"
    result = bench.restore(_encrypt_to_recipient(bench, crafted), target)
    assert result.returncode == 1 and "links" in result.stderr, result.stderr
    assert not target.exists()
    assert not list(bench.tmp.glob("restored/.curate-restore.*")), "decrypted temp left behind"


@needs_openssl3
def test_pull_keeps_only_the_newest_archives(bench: Bench) -> None:
    node_dir = bench.backup_dir / "node-a"
    node_dir.mkdir(parents=True)
    for stamp in ("20260101T000000Z", "20260102T000000Z"):
        (node_dir / f"node-a-{stamp}.tar.gz.cms").write_bytes(b"old")
    assert bench.pull(BLACKBOX_BACKUP_KEEP="2").returncode == 0
    names = [path.name for path in bench.archives()]
    assert len(names) == 2 and "node-a-20260101T000000Z.tar.gz.cms" not in names


# ---------------------------------------------------------------------------
# launchd template
# ---------------------------------------------------------------------------

def test_the_launchd_template_fills_into_a_valid_plist(tmp_path: Path) -> None:
    values = {
        "__SCRIPT__": str(PULL),
        "__NODES_FILE__": str(tmp_path / "nodes.txt"),
        "__RECIPIENT__": str(tmp_path / "backup-recipient.pem"),
        "__BACKUP_DIR__": str(tmp_path / "backups"),
        "__LOG_DIR__": str(tmp_path / "logs"),
    }
    text = PLIST_TEMPLATE.read_text()
    for placeholder, value in values.items():
        assert placeholder in text
        text = text.replace(placeholder, value)
    assert "__" not in re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)

    plist = plistlib.loads(text.encode())
    assert plist["Label"] == "ai.umanitek.blackbox-curate-backup"
    assert plist["ProgramArguments"] == ["/bin/bash", str(PULL)]
    environment = plist["EnvironmentVariables"]
    assert environment["BLACKBOX_BACKUP_RECIPIENT"] == values["__RECIPIENT__"]
    assert environment["PATH"].split(":")[0] == "/opt/homebrew/bin"
    assert set(plist["StartCalendarInterval"]) == {"Hour", "Minute"}
