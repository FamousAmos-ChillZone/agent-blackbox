"""KI-371: the LLM reviewer's key is kept where the operator keeps it, and nothing switches on unasked.

Re-running the installer used to switch the reviewer on by itself and copy the
provider key from ~/.hermes/.env into config.yaml in plain text. Now:
- a key that lives in a variable Hermes loads is saved as the variable's NAME;
- saving one way removes the other (no stale copy is left behind);
- an unattended run (no terminal) changes nothing, and a terminal run asks first;
- an earlier copy is replaced by the name on the next run;
- the installer hands a typed key over in the environment, never on the command line.
HERMES_HOME is a per-test tmp dir (root conftest).
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from _blackbox_loader import load_blackbox

reviewer_setup = load_blackbox("detection.reviewer_setup")
discovery = load_blackbox("detection.reviewer_setup.discovery")
config_mod = load_blackbox("kernel.config")
settings = load_blackbox("kernel.settings")

FAKE_KEY = "test-not-a-real-key-0001"
INSTALL_SH = Path(__file__).resolve().parents[2] / "scripts" / "blackbox-install.sh"


def _stored_llm() -> dict:
    return discovery.stored_llm_entry()


def _auto_args() -> SimpleNamespace:
    return SimpleNamespace(disable=False, provider=None, model=None, key_source=None, api_key=None,
                           auto=True, configure=False)


def _hermes_candidate() -> dict:
    return {"source": "Hermes", "provider": "openai", "model": "gpt-4o-mini", "api_key": FAKE_KEY,
            "api_key_env": "OPENAI_API_KEY"}


def test_the_config_reads_the_key_from_the_named_variable(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", FAKE_KEY)
    assert settings.write_settings({"llm": {"enabled": True, "provider": "openai", "model": "gpt-4o-mini",
                                            "api_key_env": "OPENAI_API_KEY"}})["ok"]

    cfg = config_mod.load_blackbox_config()

    assert cfg.llm_ready and cfg.llm_api_key == FAKE_KEY
    assert FAKE_KEY not in str(_stored_llm())


def test_saving_the_variable_name_removes_an_earlier_copy():
    settings.write_settings({"llm": {"enabled": True, "provider": "openai", "model": "m", "api_key": FAKE_KEY}})

    settings.write_settings({"llm": {"api_key_env": "OPENAI_API_KEY"}})

    assert _stored_llm().get("api_key_env") == "OPENAI_API_KEY" and "api_key" not in _stored_llm()


def test_saving_a_typed_key_removes_the_variable_name():
    settings.write_settings({"llm": {"api_key_env": "OPENAI_API_KEY"}})

    settings.write_settings({"llm": {"api_key": FAKE_KEY}})

    assert _stored_llm().get("api_key") == FAKE_KEY and "api_key_env" not in _stored_llm()


@pytest.mark.parametrize("name", ["OPENAI API KEY", "1ABC", "$(id)", "ÖPENAI"])
def test_a_variable_name_that_is_not_one_is_refused(name):
    updates, errors = settings._validate({"llm": {"api_key_env": name}})

    assert "llm" not in updates and any("api_key_env" in e for e in errors)


def test_an_unattended_run_switches_nothing_on(monkeypatch, capsys):
    saved = []
    monkeypatch.setattr(reviewer_setup, "_auto_llm_candidate", lambda: ("Hermes", _hermes_candidate()))
    monkeypatch.setattr(reviewer_setup, "_tty", lambda: None)
    monkeypatch.setattr(reviewer_setup.settings, "write_settings", lambda payload: saved.append(payload) or {"ok": True})

    rc = reviewer_setup.cmd_setup_llm(_auto_args())

    assert rc == 2 and saved == []
    out = capsys.readouterr().out
    assert "blackbox setup-llm" in out and FAKE_KEY not in out


def test_a_no_on_the_terminal_switches_nothing_on(monkeypatch):
    saved = []
    monkeypatch.setattr(reviewer_setup, "_auto_llm_candidate", lambda: ("Hermes", _hermes_candidate()))
    monkeypatch.setattr(reviewer_setup, "_tty", lambda: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(reviewer_setup, "_ask", lambda prompt, tty: "")
    monkeypatch.setattr(reviewer_setup.settings, "write_settings", lambda payload: saved.append(payload) or {"ok": True})

    assert reviewer_setup.cmd_setup_llm(_auto_args()) == 2 and saved == []


def test_a_key_hermes_will_not_have_at_run_time_is_not_saved_by_name(monkeypatch):
    # found in ANOTHER profile's .env: this process's Hermes will not load it
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(discovery, "_runtime_env", lambda: {})

    assert discovery.reachable_key_env(_hermes_candidate()) == ""


def test_a_key_hermes_loads_is_saved_by_name(monkeypatch):
    monkeypatch.setattr(discovery, "_runtime_env", lambda: {"OPENAI_API_KEY": FAKE_KEY})

    assert discovery.reachable_key_env(_hermes_candidate()) == "OPENAI_API_KEY"


def test_an_earlier_copy_is_replaced_by_the_name_on_the_next_run(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", FAKE_KEY)
    monkeypatch.delenv("BLACKBOX_LLM_API_KEY", raising=False)
    monkeypatch.setattr(discovery, "_runtime_env", lambda: dict(os.environ))
    settings.write_settings({"llm": {"enabled": True, "provider": "openai", "model": "gpt-4o-mini",
                                     "api_key": FAKE_KEY}})   # what the old installer left behind

    assert reviewer_setup.cmd_setup_llm(_auto_args()) == 0

    stored = _stored_llm()
    assert stored.get("api_key_env") == "OPENAI_API_KEY" and "api_key" not in stored
    assert config_mod.load_blackbox_config().llm_api_key == FAKE_KEY


def test_a_new_key_is_taken_from_the_environment_not_the_command_line(monkeypatch):
    monkeypatch.setenv("BLACKBOX_LLM_API_KEY", FAKE_KEY)

    assert reviewer_setup._resolve_key("new", "openai") == (FAKE_KEY, "")


def test_the_installer_never_puts_the_key_on_a_command_line():
    text = INSTALL_SH.read_text(encoding="utf-8")

    assert "--api-key" not in text
    assert 'BLACKBOX_LLM_API_KEY="$BLACKBOX_LLM_API_KEY" "$HERMES_BIN" blackbox setup-llm' in text
