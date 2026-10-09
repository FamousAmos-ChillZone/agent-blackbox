# Agent Blackbox — Reporter Terms (community graph)

Version: 1.1 (draft for counsel review, 2026-10-03)

## What changed in version 1.1

- The community graph now has its OWN curators (section 4): they keep a
  trusted-reporter list in the community graph itself, confirm, reject or
  defer community threats, and keep a private reputation ledger. Before, only
  Umanitek's curator did this, and only in the verified graph.
- A trusted-reporter listing lasts at most 90 days unless renewed; what it
  publishes about you is listed in section 4.
- Confirmed threats can be handed to the verified graph's owner as a bundle of
  the signed statements already public in the community graph (section 4).
- Erasure rotates your SIGNING key; your node's wallet address is not changed
  by it (section 5).

These terms apply to the OPERATOR of a machine running Agent Blackbox who
turns on community sharing (`report: true`) and records consent. Sharing is
OFF by default; nothing described here happens until you consent, and you
can withdraw at any time with `blackbox report --withdraw-consent` — sharing
stops on the next action.

## 1. What you share

When a protected agent on your machine meets a threat that the VERIFIED
threat graph already lists, or when you file a report yourself with
`blackbox report`, this node publishes a privacy-safe STATEMENT to the shared
community graph of the OriginTrail Decentralized Knowledge Graph (DKG):

- the threat's deterministic identifier (for example `dep:npm:evil-pkg@1.0.0`
  or `ioc:domain:evil.example`) and its closed, typed metadata (category,
  severity, ecosystem, a closed reason word);
- the UTC day of the statement, rounded to the day;
- your node's REPORTER ADDRESS (the DKG agent address of your node's wallet)
  and a signature by your node's reporter key;
- a weekly SIGHTING DIGEST: the verified threats your agents met that week,
  with coarse buckets (1 / 2–9 / 10–99 / 100+), never exact counts or times.

Never shared, by construction: prompts, commands, file paths, file or skill
source, secrets, LLM outputs, local-only or custom-rule findings,
vulnerability findings, the names of locally authored skills, the source
of an injection, exact times, your location, or any person's identity.

## 2. What you grant

You dedicate each statement you publish to the public domain under
**CC0 1.0** (no rights reserved) so every node on the network may read,
store, verify and act on it. The graph is shared and replicated: a published
statement cannot be deleted by you, by Umanitek or by anyone; you can
RETRACT a report (`blackbox report --retract`) and every current reader
stops counting it, but the record of the statement stays on the network.

## 3. What you promise

- **No personal data.** You will not put any person's name, contact
  details, account identifiers or other personal data into a report
  (`--name`, `--pattern`, `--reason` and every free field are for the
  threat, never for a person). The client refuses free text where it can;
  the warranty is yours where it cannot.
- **Good faith.** You report what your agents actually met or what you
  verified. Confirmed bad faith (for example, reporting planted canaries or
  flooding) removes your node from the counted-author list; the counted list
  is public.
- **Your identity.** Your reporter key and address are yours. Statements by
  other nodes under your address are rejected by every reader because they
  fail your signature.

## 4. Who sees what, and for how long

- Every node subscribed to the community graph receives your statements and
  keeps them for ITS OWN retention setting (30 days by default on current
  nodes; a replica may lengthen or disable expiry). Readers keep a counted
  threat locally for up to 90 days after its network copies expire.
- Two groups of curators read the community graph. The COMMUNITY curators
  (named in the controller map) may list you as a trusted reporter, confirm,
  reject or defer a community threat, and pause intake for up to 7 days;
  their statements can only make a threat FLAG, never block. Umanitek's
  curator (the VERIFIED graph's owner) may do the same and may also promote a
  threat into the verified graph, revoke a verified rule, and publish the kill
  list.
- Each group of curators may keep a PRIVATE reputation ledger about reporters
  on its own curator nodes: which of your reports were confirmed or rejected,
  keyed by a per-reporter random salt. Nothing from it is published. The index
  that links your key to its entry is encrypted. Erasure deletes the salt.
- A trusted-reporter listing publishes, about you: your reporter key and
  node address (already on your own reports), that you are listed, your class
  (established or partner), an organisation name for partners, and an expiry
  day. A community listing lasts at most 90 days unless renewed.
- A community curator node may run a service that signs routine statements on
  its own (a heartbeat, an acknowledgement that a report is in review, a
  confirmation of a package that a public malicious-package advisory already
  names, listings its own ledger calls for). Rejections and anything that
  accuses a reporter of bad faith are always a person's decision.
- Confirmed threats can be handed to the verified graph's owner as one file
  holding the signed statements behind them, your signed reports included, so
  the receiver can credit the original reporters. The file holds nothing that
  is not already public in the community graph.

## 5. Your rights and the tools for them

- **Access and export:** `blackbox report --export FILE` writes your key
  backup and your local ledger of every statement this node made.
- **Correction / withdrawal of a statement:** `blackbox report --retract`,
  `blackbox report --false-positive`.
- **Erasure of your identity:** `blackbox report --erase-identity --confirm`
  destroys the reporter key and every local share record, including the
  keep-alive memory, so this node can never re-publish its old statements.
  Your next report is signed by a new key; your node's WALLET address, which
  every statement also carries, is not changed by this command. Each group of
  curators deletes its ledger salt on request (crypto-shredding) and stops
  keeping your listing alive.
- **Withdraw consent:** `blackbox report --withdraw-consent`.
- Requests that need a human: the contact points in the controller map
  (one for the community curators, one for Umanitek); either forwards a
  request it cannot serve to the other.

## 6. Changes

These terms are bound to their content: your consent is recorded against
the exact text you read. When the text changes, sharing stops until you
read the new version and consent again.
