"""The closed vocabularies a sighting is described with (threat-profiles §03.2).

Every field a report gains beside its evidence is a word from one of these sets
(or a strict shape), never free text: the record says WHAT was at risk and WHAT
happened in terms anyone can read, and nothing a person typed can ride along.
The predicates live here with their vocabulary; their IRIs are built on the one
ontology namespace in :mod:`...kernel.constants` and, like every published IRI,
never change once shipped.

Pattern: Constant (frozen sets + compiled shapes), no behaviour.
"""

from __future__ import annotations

import re

from ...kernel import constants

#: What the agent was doing when it met the threat.
AGENT_ACTIONS = frozenset({"fetch", "install-package", "install-skill", "read-file", "write-file",
                           "run-command", "use-tool", "model-input"})
#: What Blackbox did about it on the reporting node.
OUTCOMES = frozenset({"blocked", "flagged"})
#: What the threat is trying to achieve.
THREAT_GOALS = frozenset({"agent-hijack", "credential-theft", "wallet-drain", "malware-delivery", "phishing-lure",
                          "command-and-control", "command-execution", "privilege-escalation", "data-exfil",
                          "unknown"})
#: What it puts at risk — always a CLASS of resource, never the resource itself (no path, no name).
RESOURCES_AT_RISK = frozenset({"cloud-credentials", "ssh-key", "api-keys", "wallet-keys", "funds", "password-store",
                               "browser-session", "system-accounts", "user-credentials", "agent-instructions",
                               "agent-tools", "host-system", "none-identified"})
#: A MITRE ATT&CK technique (``T1552.001``) or MITRE ATLAS technique (``AML.T0051``).
ATTACK_TECHNIQUE_SHAPE = re.compile(r"(?:AML\.)?T[0-9]{4}(?:\.[0-9]{3})?")
#: The subject of the verified rule a report matched — the link a reader follows
#: into its OWN copy of the verified graph for the threat's name and description.
VERIFIED_SUBJECT_SHAPE = re.compile(r"urn:defender:signal:[0-9a-f]{24}|urn:blackbox:observation:[0-9a-f]{64}")
#: Tool names the hosts ship (Hermes, OpenClaw): they travel verbatim. Anything
#: else is reported as ``mcp-tool`` or ``other`` — a private tool's name can name
#: a company or a project (threat-profiles D9).
TOOL_SHAPE = re.compile(r"(?:web|browser)_[a-z0-9_]{1,32}")
OTHER_TOOLS = frozenset({"mcp-tool", "other"})

_G = constants.BLACKBOX_ONTOLOGY
AGENT_TOOL_PRED = f"{_G}agentTool"
AGENT_ACTION_PRED = f"{_G}agentAction"
OUTCOME_PRED = f"{_G}outcome"
VERIFIED_SUBJECT_PRED = f"{_G}verifiedSubject"
THREAT_GOAL_PRED = f"{_G}threatGoal"
RESOURCE_AT_RISK_PRED = f"{_G}resourceAtRisk"
ATTACK_TECHNIQUE_PRED = f"{_G}attackTechnique"
#: sha256 of the exact signed bytes (the statement's identity, LES-033) and the
#: signer's public key — both read off the envelope, written beside it so a
#: person browsing the graph sees who signed and can check the digest.
RECORD_DIGEST_PRED = f"{_G}recordDigest"
SIGNER_KEY_PRED = f"{_G}signerKey"

#: (keyword, predicate) of every sighting field, in emission order — the builder,
#: the signer and the reader all walk this one table.
SIGHTING_FIELDS = (
    ("agent_tool", AGENT_TOOL_PRED),
    ("agent_action", AGENT_ACTION_PRED),
    ("outcome", OUTCOME_PRED),
    ("verified_subject", VERIFIED_SUBJECT_PRED),
    ("threat_goal", THREAT_GOAL_PRED),
    ("resource_at_risk", RESOURCE_AT_RISK_PRED),
    ("attack_technique", ATTACK_TECHNIQUE_PRED),
)
SIGHTING_KEYS = tuple(key for key, _ in SIGHTING_FIELDS)
#: Reader query variable (the predicate's local name) -> payload key.
SIGHTING_PAYLOAD_VARS = {predicate[len(_G):]: key for key, predicate in SIGHTING_FIELDS}
