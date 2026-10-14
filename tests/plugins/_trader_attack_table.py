"""Test helper: Trader Shield's attack table joined with what each row does.

The plugin ships the page's table (``dashboard/static/trader-shield-attacks.json``:
title, how, outcome, targets, evidence …). What a row DOES — ``tool``, ``hook``,
``args``, ``graph``, ``block_severity`` — is test data in
``trader_shield_attack_scenarios.json`` beside this file, keyed by row id: shipped
attack strings read as attacks to Hermes's plugin install scanner (catalog admission).

Usage::

    from _trader_attack_table import ATTACKS, TABLE
    local = [row for row in ATTACKS if row["proof"] == "test"]   # rows with their tool calls
"""

from __future__ import annotations

import json
from pathlib import Path

from plugins.blackbox.dashboard import protection

TABLE = json.loads((protection.TRADER_SHIELD_PAGE.parent / "trader-shield-attacks.json").read_text(encoding="utf-8"))
SCENARIOS = json.loads(Path(__file__).with_name("trader_shield_attack_scenarios.json").read_text(encoding="utf-8"))["scenarios"]
#: Scenario fields: they belong to the tests and never ship in the plugin's table.
SCENARIO_FIELDS = frozenset({"tool", "hook", "args", "graph", "block_severity"})
#: Each page row with its scenario merged in — what the tests drive through the hook.
ATTACKS = [{**row, **SCENARIOS.get(row["id"], {})} for row in TABLE["attacks"]]
