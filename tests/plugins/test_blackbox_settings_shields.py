"""Shield settings in the kernel writer: handed-in validators, per-id merge, fail-closed.

:func:`settings.write_settings` runs only the shield validators its caller hands in
(the kernel imports no shield) and stores each answer at ``shields.<id>``, merged per
id like ``detection`` per category. These tests use two fake shields; no real shield
exists yet. ``HERMES_HOME``/``BLACKBOX_HOME`` are per-test tmpdirs (root conftest).
"""

import json

import pytest
from _blackbox_loader import load_blackbox


constants = load_blackbox("kernel.constants")
settings = load_blackbox("kernel.settings")
yaml_files = load_blackbox("kernel.yaml_files")


def _config_path():
    return constants.hermes_home() / "config.yaml"


def _entry() -> dict:
    """The persisted ``plugins.entries.blackbox`` entry ({} with no config file)."""
    data = yaml_files.load_yaml(_config_path()) if _config_path().exists() else {}
    return ((data or {}).get("plugins") or {}).get("entries", {}).get("blackbox") or {}


def _fake_shield(shield_id, *, supersedes=(), refuse=None):
    """A validator that stores ``payload["shields"][shield_id]`` as its section."""
    def validate(payload):
        section = dict((payload.get("shields") or {}).get(shield_id) or {})
        errors = [refuse] if refuse and section else []
        return settings.ShieldSettings(shield_id, section, errors, tuple(supersedes))
    return validate


ALPHA, BETA = _fake_shield("alpha"), _fake_shield("beta")


def test_saving_one_shield_leaves_the_other_section_byte_identical():
    both = {"shields": {"alpha": {"enabled": True, "level": 2}, "beta": {"enabled": True, "items": ["x", "y"]}}}
    assert settings.write_settings(both, validators=(ALPHA, BETA))["ok"] is True
    beta_before = json.dumps(_entry()["shields"]["beta"])   # field order included

    result = settings.write_settings({"shields": {"alpha": {"enabled": False}}}, validators=(ALPHA, BETA))

    assert result["ok"] is True
    stored = _entry()["shields"]
    assert stored["alpha"] == {"enabled": False, "level": 2}   # merged field by field, never wholesale
    assert json.dumps(stored["beta"]) == beta_before


def test_a_shields_key_without_validators_persists_nothing_under_shields():
    result = settings.write_settings({"mode": "block", "shields": {"alpha": {"enabled": True}}})

    assert result["ok"] is True
    entry = _entry()
    assert entry["mode"] == "block" and "shields" not in entry
    assert "shields" not in result["settings"]   # the kernel's answer stays shield-free


def test_the_consent_path_persists_consent_and_nothing_under_shields(real_consent):
    real_consent.withdraw()
    payload = {"report": True, "shields": {"alpha": {"enabled": True}}}

    result = settings.write_settings(payload, sharing_consent=real_consent.for_settings(payload))

    assert result["ok"] is True and real_consent.in_force()
    entry = _entry()
    assert entry["report"] is True and "shields" not in entry


def test_superseded_keys_are_removed_in_the_same_write():
    assert settings._persist({"wallet_protection": True, "mode": "block"}) is True   # a key left by an older install
    assert _entry()["wallet_protection"] is True
    alpha = _fake_shield("alpha", supersedes=("wallet_protection", "old_alpha_key"))

    result = settings.write_settings({"shields": {"alpha": {"enabled": True}}}, validators=(alpha,))

    assert result["ok"] is True
    entry = _entry()
    assert entry["shields"]["alpha"] == {"enabled": True}
    assert "wallet_protection" not in entry and "old_alpha_key" not in entry
    assert entry["mode"] == "block"   # an unnamed key is untouched


def test_an_error_from_one_validator_writes_nothing_and_returns_the_errors():
    assert settings.write_settings({"mode": "audit", "shields": {"beta": {"enabled": True}}},
                                   validators=(ALPHA, BETA))["ok"] is True
    before = _config_path().read_bytes()
    refusing = _fake_shield("alpha", refuse="alpha.enabled must be a boolean")

    result = settings.write_settings({"mode": "block", "shields": {"alpha": {"enabled": "yes"}, "beta": {"enabled": False}}},
                                     validators=(refusing, BETA))

    assert result["ok"] is False
    assert result["errors"] == ["alpha.enabled must be a boolean"]
    assert _config_path().read_bytes() == before


def test_a_validator_that_raises_fails_the_save_closed():
    def broken(payload):
        raise ValueError("boom")

    result = settings.write_settings({"mode": "block", "shields": {"beta": {"enabled": True}}}, validators=(broken, BETA))

    assert result["ok"] is False and result["errors"] == ["shield settings could not be checked"]
    assert not _config_path().exists() or "shields" not in _entry()


@pytest.mark.parametrize("answer", [
    ("alpha", {"enabled": True}, None),                       # errors not a list: never raises
    ("alpha", {"enabled": True}, "bad"),                      # a str is never split into letters
    ("alpha", {"enabled": True}, [404]),                      # errors must be strings
    ("alpha", ["enabled"], []),                               # section must be a dict
    ("", {"enabled": True}, []),                              # a shield needs a name
    (5, {"enabled": True}, []),
    ("alpha", {"enabled": True}, [], "wallet_protection"),    # supersedes is a tuple, not a str
    ("alpha", {"enabled": True}, [], ("shields",)),           # a shield may never supersede shields
    ("alpha", {"enabled": True}),                             # too short to be an answer
])
def test_a_malformed_validator_answer_fails_the_save_closed(answer):
    assert settings._persist({"wallet_protection": True}) is True   # a key left by an older install
    before = _config_path().read_bytes()

    result = settings.write_settings({"mode": "block"}, validators=(lambda payload: answer,))

    assert result["ok"] is False and len(result["errors"]) == 1
    assert all(isinstance(error, str) for error in result["errors"])
    assert _config_path().read_bytes() == before


def test_two_validators_claiming_one_shield_id_fail_the_save_closed():
    result = settings.write_settings({"shields": {"alpha": {"enabled": True}}}, validators=(ALPHA, ALPHA))

    assert result["ok"] is False and result["errors"] == ["invalid shield settings from 'alpha'"]
    assert not _config_path().exists() or "shields" not in _entry()


def test_an_untouched_shield_does_not_apply_its_superseded_keys():
    assert settings._persist({"wallet_protection": True}) is True   # a key left by an older install
    alpha = _fake_shield("alpha", supersedes=("wallet_protection",))

    assert settings.write_settings({"mode": "block"}, validators=(alpha,))["ok"] is True

    assert _entry()["wallet_protection"] is True and "shields" not in _entry()
