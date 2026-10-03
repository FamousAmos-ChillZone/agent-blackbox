"""KI-276 (regression of KI-066) — no `blackbox` option may land under a name the Hermes CLI reads first.

Hermes parses `hermes blackbox ...` with its own top-level parser and, BEFORE
it dispatches to the plugin, reads ``version``, ``yolo``, ``oneshot`` and
``command`` from the parsed arguments. A plugin option stored under one of
those names hijacks the command: `blackbox curate manifest` (``--version``,
default 1) and `blackbox report --package-version 1.0.0` (dest ``version``)
both printed the Hermes banner instead of running (found on the C12 bench).
KI-066 renamed the report's FLAG but kept the stored name; these tests check
the stored names, on the real Hermes parser.
"""

from __future__ import annotations

import argparse

import pytest

from plugins.blackbox import cli

#: What Hermes's main() reads from the parsed arguments before it dispatches to a plugin command.
HOST_READS_FIRST = frozenset({"version", "yolo", "oneshot", "command"})


#: The one intended overlap: `blackbox chat --yolo` IS Hermes chat's --yolo (passed straight through to
#: `hermes chat`), so Hermes reading it early means exactly what the operator asked for.
INTENDED = frozenset({("blackbox chat", "yolo")})


def _walk(parser: argparse.ArgumentParser, path: str = "blackbox"):
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, child in action.choices.items():
                yield from _walk(child, f"{path} {name}")
        elif action.dest != "help":
            yield path, action.dest


def _blackbox_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="blackbox")
    cli.setup_cli(parser)
    return parser


def test_no_blackbox_option_is_stored_under_a_name_hermes_reads_first():
    clashes = sorted({f"{path}: {dest}" for path, dest in _walk(_blackbox_parser())
                      if dest in HOST_READS_FIRST and (path, dest) not in INTENDED})
    assert clashes == []


def test_the_reserved_names_are_still_what_hermes_reads():
    """If Hermes starts reading another name first, this list must grow with it."""
    import inspect

    from hermes_cli import main as hermes_main
    source = inspect.getsource(hermes_main.main)
    head = source.split("args.func(args)", 1)[0]
    for name in HOST_READS_FIRST - {"command"}:
        assert f'"{name}"' in head or f"args.{name}" in head, name
    assert "args.command" in head


#: Runs in its OWN Python process: building Hermes's parser loads the plugin a second time under
#: ``hermes_plugins.blackbox``, and that copy must not leak into the shared test process (it broke a
#: later test that runs a Blackbox background thread — KI-278).
_REAL_PARSE = """
import json, sys
from hermes_cli import main as hermes_main
from plugins.blackbox import cli
parser, subparsers = hermes_main._build_cli_parser()
if "blackbox" not in subparsers.choices:
    cli.setup_cli(subparsers.add_parser("blackbox"))
args = hermes_main._parse_cli_args(parser, subparsers, json.loads(sys.argv[1]))
print(json.dumps({"version": bool(getattr(args, "version", False)), "command": args.command,
                  "value": getattr(args, sys.argv[2], None)}))
"""


@pytest.mark.parametrize("argv, attribute, value", [
    (["blackbox", "curate", "--authority", "community", "manifest", "--curator-key", "a" * 64, "--threshold", "2",
      "--manifest-version", "3"], "manifest_version", 3),
    (["blackbox", "report", "--type", "dependency", "--ecosystem", "npm", "--name", "loadyaml", "--package-version", "1.0.0",
      "--kind", "malware", "--reason", "typosquat"], "package_version", "1.0.0"),
])
def test_the_commands_that_broke_now_reach_the_plugin_through_the_real_hermes_parser(argv, attribute, value, tmp_path):
    import json
    import os
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    env = {**os.environ, "HERMES_HOME": str(tmp_path / "hermes"), "PYTHONPATH": str(root)}
    done = subprocess.run([sys.executable, "-c", _REAL_PARSE, json.dumps(argv), attribute], cwd=root, env=env,
                          capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stderr[-2000:]
    parsed = json.loads(done.stdout.strip().splitlines()[-1])
    assert parsed == {"version": False, "command": "blackbox", "value": value}     # no banner: the plugin runs
