"""KI-363: the user's protected paths hold through the terminal, not only the file tools.

``cat .env`` and ``tar czf x.tgz ~/.ssh`` reached protected files through the
terminal while the same read through a file tool was blocked. The rule now
reads terminal commands through the shell parser: what a command READS or
copies whole counts; where a copy WRITES does not (``cp .env.example .env``
sets a project up); a template file is not the secret.
"""

from __future__ import annotations

import pytest

from plugins.blackbox.detection import detect_custom_fileaccess
from plugins.blackbox.detection.paths.shell_files import shell_file_args
from plugins.blackbox.kernel.config import DEFAULT_PROTECTED_PATHS


def _evidence(command, patterns=DEFAULT_PROTECTED_PATHS):
    findings = detect_custom_fileaccess("terminal", {"command": command}, patterns)
    assert len(findings) <= 1
    return findings[0].evidence if findings else None


@pytest.mark.parametrize("command", [
    "cat .env",
    "cat config/.env.local",
    "grep API_KEY .env",
    "base64 ~/.ssh/id_ed25519",
    "head -n 3 ~/.aws/credentials",
    "less server.pem",
])
def test_a_terminal_read_of_a_protected_file_is_found(command):
    assert _evidence(command).startswith("read path matching protected pattern")


@pytest.mark.parametrize("command", [
    "tar czf backup.tgz ~/.ssh",
    "zip -r backup.zip ~/.ssh",
    "tar czf home.tgz ~",          # the home folder holds ~/.ssh
    "rsync -a ~/ /mnt/backup/",
])
def test_copying_a_folder_that_holds_protected_files_is_found(command):
    assert _evidence(command).startswith("copy path matching protected pattern")


@pytest.mark.parametrize("command", [
    "cp .env.example .env",          # setting a project up: reads only the template
    "cat .env.example",
    "cat .env.sample",
    "source .env && npm start",      # loads the values into the shell, shows nothing
    "tar czf src.tgz ~/projects/app",
    "ls -la ~/.ssh",
    "echo PORT=3000 >> .env",
    "tar xzf release.tgz",
])
def test_ordinary_project_work_is_left_alone(command):
    assert _evidence(command) is None


def test_a_template_is_protected_when_the_pattern_names_it():
    assert _evidence("cat .env.example", [".env.example"]) is not None


def test_a_name_only_pattern_says_nothing_about_folders():
    # ".env" may sit in any folder: archiving ~/projects is not matched against it.
    assert _evidence("tar czf p.tgz ~/projects", [".env"]) is None


def test_the_finding_is_the_users_own_rule():
    [finding] = detect_custom_fileaccess("terminal", {"command": "cat .env"}, [".env"])
    assert (finding.source, finding.severity, finding.tool_name) == ("custom", "critical", "terminal")


def test_no_patterns_means_no_finding():
    assert detect_custom_fileaccess("terminal", {"command": "cat .env"}, []) == []


@pytest.mark.parametrize("command, destinations", [
    ("cp a.txt b.txt", ["b.txt"]),
    ("cp -t out/ a.txt b.txt", ["out/"]),          # -t names the destination up front
    ("tar czf out.tgz ~/.ssh", ["out.tgz"]),
    ("tar xzf in.tgz", []),                        # extracting READS the archive
    ("tar -tf in.tar", []),
    ("zip -r out.zip src/", ["out.zip"]),
    ("cat a.txt", []),
])
def test_the_parser_marks_where_a_copy_writes(command, destinations):
    assert [arg.path for arg in shell_file_args(command) if arg.destination] == destinations
