"""Blackbox reads its credentials only through Hermes (plugin catalog rule 11).

``kernel.host_secrets.read_host_secret`` is the one route: it answers what
``agent.secret_scope`` gives the profile being served, falls back to the process
environment only outside Hermes, and under multiplexing with no scope it answers
"" instead of another profile's key. These tests run the real secret_scope, not a stub.
"""

from __future__ import annotations

import logging

import pytest
from _blackbox_loader import load_blackbox

from agent import secret_scope

host_secrets = load_blackbox("kernel.host_secrets")
config_mod = load_blackbox("kernel.config")
discovery = load_blackbox("detection.reviewer_setup.discovery")

SCOPED_VALUE = "scoped-test-value"
PROCESS_VALUE = "process-test-value"


@pytest.fixture
def profile_scope():
    """Install a Hermes profile scope holding *mapping* for the test, then remove it."""
    tokens = []

    def install(mapping):
        tokens.append(secret_scope.set_secret_scope(mapping))

    yield install
    for token in reversed(tokens):
        secret_scope.reset_secret_scope(token)


def test_the_served_profile_value_wins_over_the_process_environment(monkeypatch, profile_scope):
    monkeypatch.setenv("BLACKBOX_TEST_KEY", PROCESS_VALUE)
    profile_scope({"BLACKBOX_TEST_KEY": SCOPED_VALUE})

    assert host_secrets.read_host_secret("BLACKBOX_TEST_KEY") == SCOPED_VALUE


def test_multiplexing_without_a_scope_gives_no_key_and_warns(monkeypatch, caplog):
    monkeypatch.setenv("BLACKBOX_TEST_KEY", PROCESS_VALUE)   # another profile's value in os.environ
    token = secret_scope.set_multiplex_context(True)
    try:
        with caplog.at_level(logging.WARNING):
            value = host_secrets.read_host_secret("BLACKBOX_TEST_KEY")
    finally:
        secret_scope.reset_multiplex_context(token)

    assert value == ""
    assert "no profile scope" in caplog.text


@pytest.mark.parametrize("name", ["", "NOT A NAME", "../.env", "KEY=VALUE", "CLÉ"])
def test_a_name_that_is_not_a_variable_is_never_read(name):
    assert host_secrets.read_host_secret(name) == ""


def test_the_reviewer_key_comes_from_the_served_profile(monkeypatch, profile_scope):
    monkeypatch.setenv("BLACKBOX_LLM_API_KEY", PROCESS_VALUE)
    profile_scope({"BLACKBOX_LLM_API_KEY": SCOPED_VALUE})

    assert config_mod.load_blackbox_config().llm_api_key == SCOPED_VALUE


def test_discovery_reads_no_env_file_and_no_other_program(tmp_path, monkeypatch):
    """A key that exists only in a .env file or OpenClaw's config is not found: the operator pastes it."""
    from hermes_cli import config as hconfig

    (tmp_path / ".env").write_text("OPENAI_API_KEY=file-only-value\n", encoding="utf-8")
    (tmp_path / "openclaw.json").write_text('{"model": {"provider": "openai", "apiKey": "x"}}', encoding="utf-8")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(hconfig, "load_config", lambda: {"model": {"provider": "openai", "api_key": "in-config"}})

    assert discovery._hermes_llm_candidate() is None
