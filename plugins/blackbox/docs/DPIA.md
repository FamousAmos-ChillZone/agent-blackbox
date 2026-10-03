# Data Protection Impact Assessment — Agent Blackbox community graph

Version: 1.3 (draft for counsel review, 2026-10-03; v1.3 adds the community authority — Community Curation C11; v1.2 corrected §2/§5 after review round 5 — KI-221/223/224, erasure semantics KI-220). Engineering assessment,
not legal advice; the launching party still needs counsel for its market.

## 1. The processing

Agent Blackbox nodes (run by node OPERATORS) publish privacy-safe threat
statements to a shared, replicated graph (the OriginTrail DKG, "community
graph"). Two groups of curators read them: the COMMUNITY curators keep a
trusted-reporter list and verdicts in the community graph itself (flag only),
and Umanitek's curator may promote threats into the verified graph that every
node enforces. Every node verifies signatures and computes stages itself.
No new kind of personal data is collected by adding the community curators;
what changes is who decides about the data and where the decisions live. Purpose: early warning about malicious packages, skills, MCP
servers, prompt-injection patterns and indicators of compromise met by AI
agents, so other agents are protected sooner.

## 2. Personal data inventory (what, why, where, how long)

| Data | Purpose | Where it lives | Retention |
| --- | --- | --- | --- |
| Reporter address (the node wallet's DKG agent address) and reporter public key | identity binding: every statement is signed; readers count distinct reporters | every community-graph replica; trusted-reporter listings in the verified graph and in the community graph | per replica's own expiry (30 d default; a replica may disable expiry → unbounded); verified listings ≤ 12 months, community listings ≤ 90 days, both renewable; each curator node re-publishes only its CURRENT statements |
| Trusted-reporter listing (listed yes/no, class, partner organisation, expiry day) | which reporters' reports count | as above | as above; a delisting is in force at most 12 months |
| Reader trust store (`community_trust.json`: the curator statements and key manifests this node verified, listings included) | keep working when the graph cannot be read | every reader's own machine | current statements only, nothing older than 500 days; pruned on every read |
| Export bundle of the confirmed pool (signed confirmations, the signed reports behind them, listings of those reporters) | hand-off to the verified graph's owner | wherever the receiver keeps the file | the receiver's own retention; holds nothing not already public |
| Threat statements (identifier, closed metadata, day) signed by the reporter | the product's purpose | every replica | as above; readers keep a counted threat ≤ 90 d past expiry locally |
| Weekly sighting digest (verified threats met, coarse buckets) | frequency signal | every replica | as above |
| Share ledger (what this node shared, outcomes) | the operator's own record, rights (export) | the operator's machine only | until erased by the operator |
| Keep-alive memory (signed quads of accepted reports) | re-publishing copies before expiry | the operator's machine only | retired at the threat type's lifetime (47–460 d); erased with the identity |
| Curator reputation ledger (outcomes per reporter, credited automatically from published verdicts) | graduation / demotion decisions | each curator group's own curator nodes, pseudonymised by a per-reporter random salt; the index from key to salt is encrypted, its key in a third owner-only file (KI-257) | inactive entries deleted after 24 months together with their salts; erasure deletes the salt (crypto-shredding) |
| Curator node records (proposals, the consent ledger of what was published and why, the node's own share ledger entry for each published statement, the statements kept alive, the automation-policy acceptance, the service's daily count) | accountability for every statement signed under a curator key | the curator node only | proposals and the consent ledger are kept as the record of published acts; statements kept alive are retired when no longer current or on erasure |
| Canaries (planted identifiers) | detecting bad-faith reporters | the curator node only | curator's discretion |
| Local audit logs on an operator's machine | the operator's own visibility | the operator's machine, redacted at capture | the operator's log rotation |
| Private audit record (identifier, severity, REDACTED evidence text ≤ 1200 chars, exact time) | the operator's own forensic trail | the operator's OWN DKG node's private working memory, never shared; written only when the node is on the same machine (a remote `dkg_url` disables it, KI-223) | the node's working-memory retention |
| Weekly sighting tally (verified-threat identifiers met, per ISO week) | source of the weekly digest | the operator's machine only | 8 weeks; erased with the identity (KI-221) |

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
| Reputation ledger profiling | Curator-private, salted pseudonyms, encrypted index, 24-month retention, erasure by salt deletion; decisions reach readers only as list entries |
| Automated decisions about reporters (the curator service lists or delists a reporter when its ledger calls for it) | The rules are arithmetic over public outcomes, written in the automation policy the operator accepted; two curator nodes must each reach the same answer from their own ledgers; strikes and anything alleging bad faith are always a person's; the reporter sees its own progress (`blackbox report --standing`) and can dispute and retract |
| A second group of controllers (the community curators) | Separate root keys: neither group can speak for the other; the controller map names both; the terms changed, so every operator is asked to consent again before sharing |
| The export bundle spreads reporters' signed reports to a new receiver | It holds only statements already public in the community graph; reporters are told in the terms; crediting reporters is its purpose |
| A breach of the curator ledger | Copying the entries file or the index alone links no key to any outcome (the index is encrypted); all three files together do, so the key file is the one to protect |
| Re-identification of a node from its address | The address is a wallet, pseudonymous by design; the terms warn; no mapping to persons is kept anywhere in the product |
| Children's or special-category data | None is collected; the schema has no field for it |
| Breach | Statements are public by design; the private surfaces (ledger, canaries, audit logs) are files on single machines with owner-only modes. The ledger is two files: the entries (pseudonym → outcomes) and the salt map (reporter key → salt, owner-only, pruned with its entry); a breach of the entries file alone links no key to any outcome, a breach of both does — the salt map is the file to protect |

## 5. Rights operations

| Right | Operation |
| --- | --- |
| Access / export | `blackbox report --export FILE` (key backup, ledger, consent record, keep-alive memory, retry queue, sighting tally — machine-readable JSON, KI-224) |
| Rectification | `--retract`, `--false-positive` |
| Erasure | `--erase-identity --confirm` (signing key, ledger, keep-alive memory, retry queue, consent record, sighting tally); on request, each curator group runs `blackbox curate graduate --erase KEY` (salt deletion, and its statements about the reporter are no longer kept alive). NOTE (KI-220): erasure rotates the SIGNING key; the reporter address in every statement is the node's wallet address, which this command does not change — a new reporter identity in full needs a new node wallet (decision pending) |
| Restriction / objection | `--withdraw-consent`; `report: false` |
| Portability | the export file restores the identity on another machine (`--restore-key`) |

## 6. Transfers and sub-processors

The DKG is a peer-to-peer network; replicas may be anywhere. No processor
acts on Umanitek's behalf for the community graph itself; the curator node's
hosting provider is a sub-processor for the curator-private files (named in
the controller map).

## 7. Open items for counsel

- Name the community curators' operator and its contact point (decision 15);
  until then, no reporter outside the pilot.
- Confirm that automated listing and delisting by the curator service, with
  the safeguards above, is acceptable (GDPR art. 22).

- Confirm the joint-controller analysis (controller map §2).
- Confirm CC0 as the licence for statements.
- Confirm the 24-month ledger retention and the 90-day reader persistence.
- Decide whether the counted-author list needs a published privacy notice of its own.

## 8. Compliant-by-default checklist (run 2026-10-03, Community Curation C11)

| Item | State | Where |
| --- | --- | --- |
| Only necessary fields, each mapped to a purpose | done | §2: no new kind of personal data; listings carry key, address, class, organisation, expiry |
| Consent opt-in, unbundled, default off; record stored; withdrawal works | done | §3; bound to the terms' text, so the v1.1 terms ask every operator again and say why; a node with `report: true` and no current consent shows an ACTION item in `blackbox status` and the dashboard |
| Access, export, correction, deletion, opt-out are real, tested operations | done | §5; the curator-side erasure removes the ledger entry and ends keep-alive of statements about the reporter |
| Retention set; automatic deletion | done | §2: replica expiry, 90-day community listings, 24-month ledger, 500-day trust store, current-only keep-alive |
| Encryption at rest for the sensitive store; secrets kept out of statements | done | the ledger index is encrypted (AES-256-GCM); keys and tokens never leave their owner-only files |
| No personal data in logs | done | statements carry no free text; display strings are sanitized; the consent ledger records codes and summaries, never report content |
| Sensitive and children's data | not applicable | the schema has no field for it |
| Sub-processors and data locations; transfer basis | done, one name open | controller map §1, §3, §4; the community curators' operator is to be named (decision 15) |
| Breach detection and runbook for the 72-hour clock | partly | statements are public by design; curator nodes alarm on manifest conflicts, silence and floods; a written runbook for a curator-node compromise belongs to the launch gate (C13) |
| Privacy notice matches the code | done | reporter terms v1.1, this DPIA v1.3, controller map v1.1, all revised in the same change as the code they describe |

Open, outside engineering: counsel review of these three documents before the
first reporter outside the pilot.
