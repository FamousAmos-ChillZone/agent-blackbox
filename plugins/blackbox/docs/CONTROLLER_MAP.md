# Controller map — Agent Blackbox community graph

Version: 1.1 (draft for counsel review, 2026-10-03 — the community authority added)

## 1. The parties

| Party | Role in the processing | What it decides | What it holds |
| --- | --- | --- | --- |
| **Node operator** (whoever runs an Agent Blackbox node with `report: true`) | controller for the statements its node publishes | whether to share at all (consent), what to report manually, when to retract, withdraw or erase | the reporter key, the share ledger, the keep-alive memory, local audit logs |
| **Umanitek** (operator of the curator node and publisher of the verified graph) | controller for the curator's processing | which threats are confirmed, rejected, attested, promoted or revoked; who is a counted author; the kill list; the reporter terms | the curator-private reputation ledger (salted), canaries, proposals and consent records of the two-key flow |
| **Community curators' operator** (runs the community curator nodes and holds the community root key) — NAME TO BE RECORDED before the first reporter outside the pilot (decision 15, open) | controller for the community authority's processing | who is a trusted reporter in the community graph; which community threats are confirmed, rejected, deferred; intake pauses; the automation policy its curator service runs under | the community curators' private reputation ledger (salted, index encrypted), their proposals and consent records, the statements they keep alive, the policy acceptance |
| **Every other node** (readers) | independent controller of its own replica | its own retention setting (TTL), its own local overrides | its replica of the community graph |
| **Curator node hosting provider** | processor for Umanitek | nothing | the curator node's disk |
| **Community curator node hosting provider** | processor for the community curators' operator | nothing | the community curator nodes' disks |

## 2. Joint controllership

Umanitek, the community curators' operator and the node operators jointly
determine the purpose (threat early warning) and the means (the statement
schema, the graph, the stages) of the community graph. Each curator group
decides alone about its own reputation ledger and its own verdicts; neither
can make a statement in the other's name (separate root keys). The essence
of the arrangement (GDPR art. 26):

- **Transparency:** the reporter terms (shipped in the client, bound to
  consent) tell operators what is published; this map and the DPIA are
  published with the product.
- **Rights:** the operator serves access, export, rectification and erasure
  for its own node's data with the client's commands; each curator group
  serves erasure of its own ledger entry (salt deletion, and its listing is no
  longer kept alive) and answers requests about its own decisions. Any party
  forwards a request it cannot serve to the right one within 7 days.
- **Contact points for data subjects:** Umanitek: privacy@umanitek.ai.
  Community curators: TO BE RECORDED with the operator's name (decision 15).

## 3. Where data physically lives

- Community graph statements: on every subscribed node's replica, wherever
  that node runs (peer-to-peer; no central store).
- Verified graph: on every node's replica; published from the curator node.
- Curator-private files: on each curator group's own curator nodes (hosting
  providers named in the current deployment record; updated when they change).
- Export bundles of the confirmed pool: wherever their receiver keeps them;
  they hold only statements already public in the community graph.
- Operator-private files: on the operator's machine.

## 4. Cross-border transfers

Replication is global by design; the data replicated is pseudonymous
(wallet addresses) and purpose-limited (threat identifiers). The basis for
any transfer outside the EEA is the operator's explicit consent to publish
into a public network (GDPR art. 49(1)(a)) for the statements, and the
curator's legitimate interest in network security for its reads. Counsel to
confirm.
