# Agent Blackbox — Reporter Terms (community graph)

Version: 1.0 (draft for counsel review, 2026-10-02)

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
- Umanitek's curator node reads the community graph, may confirm, reject,
  attest a stage for, or promote a threat into the verified graph, and keeps
  a PRIVATE reputation ledger about reporters keyed by a per-reporter random
  salt; nothing from that ledger is published. Erasure deletes the salt.
- The counted-author list (which reporter addresses count, and in which
  class) is published in the verified graph.

## 5. Your rights and the tools for them

- **Access and export:** `blackbox report --export FILE` writes your key
  backup and your local ledger of every statement this node made.
- **Correction / withdrawal of a statement:** `blackbox report --retract`,
  `blackbox report --false-positive`.
- **Erasure of your identity:** `blackbox report --erase-identity --confirm`
  destroys the reporter key and every local share record, including the
  keep-alive memory, so this node can never re-publish its old statements;
  the curator deletes the ledger salt on request (crypto-shredding).
- **Withdraw consent:** `blackbox report --withdraw-consent`.
- Requests that need a human: privacy@umanitek.ai (joint controllers, see
  the controller map).

## 6. Changes

These terms are bound to their content: your consent is recorded against
the exact text you read. When the text changes, sharing stops until you
read the new version and consent again.
