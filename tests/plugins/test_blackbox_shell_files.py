"""The shell channel's file view (detection/shell_files.py).

A path rule only protects a file if it sees every way the agent reaches it;
these tests pin which commands count, how words are split, and which
arguments are taken as whole folders.
"""

from __future__ import annotations

from plugins.blackbox.detection import action_parsing
from plugins.blackbox.detection.shell_files import shell_file_args


def _paths(command):
    return [(arg.path, arg.command, arg.recursive) for arg in shell_file_args(command)]


def test_escaped_space_keeps_a_macos_path_whole():
    assert _paths("cat ~/Library/Application\\ Support/Google/Chrome/Default/x.log") == [
        ("~/Library/Application Support/Google/Chrome/Default/x.log", "cat", False),
    ]


def test_quoted_path_with_spaces_is_one_argument():
    assert _paths('cp -r "$HOME/Library/Application Support/BraveSoftware" /tmp/out') == [
        ("$HOME/Library/Application Support/BraveSoftware", "cp", True),
        ("/tmp/out", "cp", True),
    ]


def test_archive_commands_take_folders_whole():
    assert [arg.recursive for arg in shell_file_args("tar czf out.tgz ~/.config")] == [True, True]
    assert [arg.recursive for arg in shell_file_args("zip -r out.zip ~/.config")] == [True, True]
    assert [arg.recursive for arg in shell_file_args("ditto -c -k ~/Library x.zip")] == [True, True]


def test_grep_reads_folders_only_with_a_recursive_flag():
    assert _paths("grep -r seed ~/.config") == [("~/.config", "grep", True)]
    assert _paths("grep -Rn seed ~/.config") == [("~/.config", "grep", True)]
    assert _paths("grep seed notes.txt") == [("notes.txt", "grep", False)]


def test_each_command_after_a_separator_is_its_own():
    assert _paths("cd /tmp && cat a.txt | base64 > b.txt; ls ~/x") == [
        ("a.txt", "cat", False),
    ]


def test_command_named_by_full_path_is_recognised():
    assert _paths("/bin/cat ~/.ssh/id_rsa") == [("~/.ssh/id_rsa", "cat", False)]


def test_windows_paths_keep_their_backslashes():
    assert _paths(r"type C:\Users\a\AppData\Local\x.ldb & echo hi") == [
        (r"C:\Users\a\AppData\Local\x.ldb", "type", False),
    ]
    assert _paths(r'Compress-Archive -Path "%LOCALAPPDATA%\Google\Chrome\User Data" -DestinationPath o.zip') == [
        (r"%LOCALAPPDATA%\Google\Chrome\User Data", "compress-archive", True),
        ("o.zip", "compress-archive", True),
    ]


def test_unbalanced_quote_still_yields_paths():
    assert _paths("cat ~/.ssh/id_rsa 'oops") == [("~/.ssh/id_rsa", "cat", False)]


def test_commands_that_touch_no_file_yield_nothing():
    assert _paths("echo hello && ls -la && pwd") == []
    assert _paths("") == []


def test_parse_shell_reads_keeps_its_contract():
    assert action_parsing.parse_shell_reads("cat ~/.ssh/id_rsa && head -5 package.json") == ["~/.ssh/id_rsa", "package.json"]
