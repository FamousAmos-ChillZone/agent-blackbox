# Data Protection Impact Assessment — Agent Blackbox community graph

Version: 1.0 (draft for counsel review, 2026-10-02). Engineering assessment,
not legal advice; the launching party still needs counsel for its market.

## 1. The processing

Agent Blackbox nodes (run by node OPERATORS) publish privacy-safe threat
statements to a shared, replicated graph (the OriginTrail DKG, "community
graph"); Umanitek's curator node reads them, verifies signatures, computes
stages, and may promote threats into the verified graph that every node
enforces. Purpose: early warning about malicious packages, skills, MCP
servers, prompt-injection patterns and indicators of compromise met by AI
agents, so other agents are protected sooner.

## 2. Personal data inventory (what, why, where, how long)

| Data | Purpose | Where it lives | Retention |
| --- | --- | --- | --- |
| Reporter address (the node wallet's DKG agent address) and reporter public key | identity binding: every statement is signed; readers count distinct reporters | every community-graph replica; the counted-author list in the verified graph | per replica's own expiry (30 d default; a replica may disable expiry → unbounded); counted-author listings ≤ 12 months, renewable |
| Threat statements (identifier, closed metadata, day) signed by the reporter | the product's purpose | every replica | as above; readers keep a counted threat ≤ 90 d past expiry locally |
| Weekly sighting digest (verified threats met, coarse buckets) | frequency signal | every replica | as above |
| Share ledger (what this node shared, outcomes) | the operator's own record, rights (export) | the operator's machine only | until erased by the operator |
| Keep-alive memory (signed quads of accepted reports) | re-publishing copies before expiry | the operator's machine only | retired at the threat type's lifetime (47–460 d); erased with the identity |
| Curator reputation ledger (outcomes per reporter) | graduation / demotion decisions | the curator node only, pseudonymised by a per-reporter random salt | inactive entries deleted after 24 months; erasure deletes the salt (crypto-shredding) |
| Canaries (planted identifiers) | detecting bad-faith reporters | the curator node only | curator's discretion |
| Local audit logs on an operator's machine | the operator's own visibility | the operator's machine, redacted at capture | the operator's log rotation |

Never processed: prompts, commands, paths, file/skill source, secrets, LLM
outputs, vulnerability findings, the names of locally authored skills, the
source of an injection, exact times (days only), locations, end-user
identities. Enforced by the client's closed report schema and the
never-shared source list; tested.

## 3. Lawful basis and consent

- Node operators: consent, opt-in, default OFF, bound to the content of the
  reporter terms (sha256), withdrawable with one command that stops the
  processing on the next action (R13 consent record).
- Legitimate interest (network and information security, GDPR recital 49) is
  the fallback basis for the curator's processing of statements that nodes
  chose to publish into a public graph.

## 4. Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| Immutable statements cannot be deleted from a replicated graph | The terms say so before consent; retraction stops counting on every current reader; nothing identifying beyond the reporter address is ever in a statement |
| Author linkability: a reporter's dependency reports reveal which packages its agents install | Day-rounded timestamps; automatic sightings only for VERIFIED-tier matches; vulnerability findings never leave; the operator may run a dedicated reporter identity and erase it |
| The weekly digest is a week-level list of verified threats per address | Coarse buckets; verified threats only; the digest is one statement per week; opt-in like every share |
| A replica disables expiry → unbounded retention | Disclosed in the terms; readers' own persistence is bounded (≤ 90 d past expiry); the inventory records the replica setting as the retention boundary |
| The counted-author list is public | It carries addresses and classes only; graduation needs the reporter's own reports; delisting is one statement |
| Reputation ledger profiling | Curator-private, salted pseudonyms, 24-month retention, erasure by salt deletion; decisions reach readers only as list entries |
| Re-identification of a node from its address | The address is a wallet, pseudonymous by design; the terms warn; no mapping to persons is kept anywhere in the product |
| Children's or special-category data | None is collected; the schema has no field for it |
| Breach | Statements are public by design; the private surfaces (ledger, canaries, audit logs) are files on single machines with owner-only modes; a breach of the curator ledger exposes salted pseudonyms and outcomes only |

## 5. Rights operations

| Right | Operation |
| --- | --- |
| Access / export | `blackbox report --export FILE` (key backup + ledger, machine-readable JSON) |
| Rectification | `--retract`, `--false-positive` |
| Erasure | `--erase-identity --confirm` (key, ledger, keep-alive memory, retry queue, consent record); curator salt deletion on request |
| Restriction / objection | `--withdraw-consent`; `report: false` |
| Portability | the export file restores the identity on another machine (`--restore-key`) |

## 6. Transfers and sub-processors

The DKG is a peer-to-peer network; replicas may be anywhere. No processor
acts on Umanitek's behalf for the community graph itself; the curator node's
hosting provider is a sub-processor for the curator-private files (named in
the controller map).

## 7. Open items for counsel

- Confirm the joint-controller analysis (controller map §2).
- Confirm CC0 as the licence for statements.
- Confirm the 24-month ledger retention and the 90-day reader persistence.
- Decide whether the counted-author list needs a published privacy notice of its own.
