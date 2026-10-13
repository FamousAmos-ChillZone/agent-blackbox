"""Trader Shield's full event report (dashboard/protection/events.py) — local detail, never shared.

The report window shows each wallet event with what the agent was asked, the exact
command, and the session around it. These tests drive the REAL hooks (session start,
model request, the blocked tool call, session end) into a throwaway Blackbox home and
read the report back, so the window is proven against what the hooks actually write.
"""

from __future__ import annotations

import secrets

import pytest

from plugins.blackbox import ruleset as ruleset_mod
from plugins.blackbox.community import sharing as community_sharing
from plugins.blackbox.dashboard.protection import events as wallet_events
from plugins.blackbox.detection import wallet_files
from plugins.blackbox.guard import background as guard_background
from plugins.blackbox.guard import hooks
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.kernel.crypto_secrets import wallet_mode
from plugins.blackbox.ruleset import Ruleset

CHROME_ID = "nkbihfbeogaeaoehlefnkodbefgpgknn"
SESSION = "20261012_222922_218e43"
ARCHIVE_CHROME = "tar czf /tmp/chrome-backup.tgz ~/.config/google-chrome"
REQUEST = "Please back up my Chrome profile with tar and tell me the result."


@pytest.fixture
def shielded(tmp_path, monkeypatch):
    """A machine with MetaMask in Chrome, Trader Shield engaged, block mode, no network."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    vault = tmp_path / ".config" / "google-chrome" / "Default" / "Local Extension Settings" / CHROME_ID
    vault.mkdir(parents=True)
    (vault / "000003.log").write_text("vault", encoding="utf-8")
    wallet_files.EXISTING_STORES.reset()
    monkeypatch.setattr(hooks, "_config", lambda: config_mod.BlackboxConfig(mode="block", report=False))
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: Ruleset())
    monkeypatch.setattr(guard_background, "_spawn_osv_discovery", lambda *a, **k: None)
    monkeypatch.setattr(guard_background, "_spawn_auto_attach", lambda *a, **k: None)
    monkeypatch.setattr(wallet_mode, "current", lambda: wallet_mode.WalletProtection(enabled=True))
    yield tmp_path
    wallet_files.EXISTING_STORES.reset()


def _run_session(command, request=REQUEST, tool_call_id="call_1"):
    """One agent session as Hermes drives the hooks: start, ask the model, call a tool, end."""
    hooks.on_session_start(session_id=SESSION)
    hooks.on_pre_api_request(session_id=SESSION, task_id="t1", turn_id="t1:1", model="gpt-4.1-mini",
                             provider="openai-api", user_message=request,
                             request_messages=[{"role": "user", "content": request}])
    result = hooks.on_pre_tool_call(tool_name="terminal", args={"command": command},
                                    session_id=SESSION, task_id="t1", tool_call_id=tool_call_id)
    hooks.on_post_tool_call(tool_name="terminal", args={"command": command}, result='{"error": "blocked"}',
                            session_id=SESSION, task_id="t1", tool_call_id=tool_call_id)
    hooks.on_session_end(session_id=SESSION)
    return result


def test_a_blocked_vault_copy_is_reported_with_its_request_command_and_session(shielded):
    assert _run_session(ARCHIVE_CHROME)["action"] == "block"

    [event] = wallet_events.wallet_event_report()["events"]

    assert event["outcome"] == "blocked" and event["identifier"].endswith(":crypto-wallet")
    assert "MetaMask" in event["title"] and event["tool"] == "terminal"
    assert event["command"] == ARCHIVE_CHROME
    assert event["asked"] == REQUEST
    assert event["session"]["model"] == "gpt-4.1-mini" and event["session"]["status"] == "completed"


def test_the_timeline_marks_the_step_that_reached_for_the_wallet(shielded):
    _run_session(ARCHIVE_CHROME)

    [event] = wallet_events.wallet_event_report()["events"]
    steps = event["timeline"]

    assert [step["type"] for step in steps if step["type"] in ("api", "tool")] == ["api", "tool"]
    [this_step] = [step for step in steps if step["this"]]
    assert this_step["label"] == ARCHIVE_CHROME and this_step["threats"] == ["blocked"]


def test_ordinary_commands_and_other_threats_are_not_wallet_events(shielded):
    _run_session("ls -la ~/projects")
    assert wallet_events.wallet_event_report()["events"] == []


def test_a_secret_in_the_request_or_command_is_redacted_in_the_report(shielded):
    token = "sk-proj-" + secrets.token_hex(24)   # built at runtime: no secret-shaped literal in the repo
    _run_session(ARCHIVE_CHROME + " # OPENAI_API_KEY=" + token, request=REQUEST + " key " + token)

    [event] = wallet_events.wallet_event_report()["events"]

    assert token not in str(event) and token[8:] not in str(event)


def test_a_long_session_keeps_the_steps_nearest_the_event():
    session_steps = [{"type": "tool", "ts": n, "action": "step %d" % n, "threats": []} for n in range(100)]
    window = wallet_events._timeline(session_steps, 70)
    assert len(window) == wallet_events.MAX_TIMELINE_STEPS
    assert [step["label"] for step in window if step["this"]] == ["step 70"]
    assert window[0]["label"] == "step %d" % (70 - wallet_events.MAX_TIMELINE_STEPS // 2)


def test_a_wallet_event_never_leaves_the_machine(shielded, monkeypatch):
    """The detail is local by construction: the real wallet finding's source is one the
    community share gate never sends, so neither it nor its context is ever reported."""
    captured = []
    monkeypatch.setattr(hooks.reporting, "_report_and_audit",
                        lambda cfg, event, findings, detail: captured.extend(findings))
    hooks.on_pre_tool_call(tool_name="terminal", args={"command": ARCHIVE_CHROME}, session_id=SESSION)
    [finding] = captured
    cfg = config_mod.BlackboxConfig(report=True, community_graph_id="did:dkg:context-graph:test")

    allowed, why = community_sharing.CommunitySharePolicy(cfg).decide(finding.to_dict(), "0x" + "ab" * 20)

    assert allowed is False and "never leaves the machine" in why


def test_the_report_is_served_only_by_the_dashboard_route(shielded):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from plugins.blackbox.dashboard import protection

    _run_session(ARCHIVE_CHROME)
    app = FastAPI()
    protection.register_protection_routes(app)
    body = TestClient(app).get("/api/wallet-protection/events").json()
    assert body["private"] is True and body["events"][0]["outcome"] == "blocked"


def test_a_threat_met_earlier_in_the_session_is_named_on_the_way_to_the_wallet(shielded, monkeypatch):
    """The chain: something the agent read raised a threat first; the wallet event's timeline
    names it, so the report can say the agent was being steered."""
    from plugins.blackbox import audit

    hooks.on_session_start(session_id=SESSION)
    audit.record(event="pre_api_request",
                 findings=[{"identifier": "injection:test", "category": "injection", "severity": "high",
                            "title": "Instruction override — 'ignore previous instructions'", "source": "public"}],
                 detail={"session_id": SESSION, "model": "gpt-4.1-mini", "decision": "flag"})
    hooks.on_pre_tool_call(tool_name="terminal", args={"command": ARCHIVE_CHROME}, session_id=SESSION, tool_call_id="c1")
    hooks.on_session_end(session_id=SESSION)

    [event] = wallet_events.wallet_event_report()["events"]
    earlier = [step for step in event["timeline"] if step["threat_titles"] and not step["this"]]

    assert earlier and "ignore previous instructions" in earlier[0]["threat_titles"][0]
    assert earlier[0]["label"] == "Threat found in what the agent was given"


def test_the_wallet_logo_is_served_only_for_a_supported_wallet():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from plugins.blackbox.dashboard import protection

    app = FastAPI()
    protection.register_protection_routes(app)
    client = TestClient(app)
    logo = client.get("/wallets/metamask.svg")
    assert logo.status_code == 200 and logo.headers["content-type"].startswith("image/svg+xml")
    assert client.get("/wallets/..%2Fserver.svg").status_code == 404
    assert client.get("/wallets/phantom.svg").status_code == 404
