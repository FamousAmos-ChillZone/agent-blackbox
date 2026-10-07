"""The Windows installer is valid PowerShell (parsed by PowerShell itself).

PowerShell parses the whole script before running a line, so one syntax error
stops the installer before it does anything. 6ef34b9a00 (KI-294, 2026-10-07)
added two error messages with "origin/$RepoBranch: ..." — `$RepoBranch:` reads
as a scope-qualified variable — and every Windows install would have failed;
the string checks in the other installer tests could not see it. Skips (with
the reason) when no PowerShell is installed; GitHub's Linux runners ship pwsh.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

INSTALL_PS1 = Path(__file__).resolve().parents[1] / "scripts" / "blackbox-install.ps1"
PWSH = os.environ.get("BLACKBOX_TEST_PWSH") or shutil.which("pwsh")

# The path goes in through the environment, never as a command-line argument:
# `pwsh -Command <script> <path>` appends <path> to the COMMAND and runs the
# installer (it did, once, while this test was written). This only parses.
PARSE = r"""
$text = [System.IO.File]::ReadAllText($env:BLACKBOX_PS1_UNDER_TEST, [System.Text.Encoding]::UTF8)
$tokens = $null; $errors = $null
[void][System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
foreach ($e in $errors) { "line {0}: {1}" -f $e.Extent.StartLineNumber, $e.Message }
"""


@pytest.mark.skipif(PWSH is None, reason="PowerShell (pwsh) is not installed")
def test_the_windows_installer_has_no_powershell_syntax_errors() -> None:
    result = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-Command", PARSE],
                            capture_output=True, text=True, timeout=120,
                            env={**os.environ, "BLACKBOX_PS1_UNDER_TEST": str(INSTALL_PS1)})

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "", result.stdout
