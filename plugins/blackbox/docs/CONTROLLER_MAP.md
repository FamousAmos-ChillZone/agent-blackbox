# Controller map — Agent Blackbox community graph

Version: 1.0 (draft for counsel review, 2026-10-02)

## 1. The parties

| Party | Role in the processing | What it decides | What it holds |
| --- | --- | --- | --- |
| **Node operator** (whoever runs an Agent Blackbox node with `report: true`) | controller for the statements its node publishes | whether to share at all (consent), what to report manually, when to retract, withdraw or erase | the reporter key, the share ledger, the keep-alive memory, local audit logs |
| **Umanitek** (operator of the curator node and publisher of the verified graph) | controller for the curator's processing | which threats are confirmed, rejected, attested, promoted or revoked; who is a counted author; the kill list; the reporter terms | the curator-private reputation ledger (salted), canaries, proposals and consent records of the two-key flow |
| **Every other node** (readers) | independent controller of its own replica | its own retention setting (TTL), its own local overrides | its replica of the community graph |
| **Curator node hosting provider** | processor for Umanitek | nothing | the curator node's disk |

## 2. Joint controllership

Umanitek and the node operators jointly determine the purpose (threat early
warning) and the means (the statement schema, the graph, the stages) of the
community graph. The essence of the arrangement (GDPR art. 26):

- **Transparency:** the reporter terms (shipped in the client, bound to
  consent) tell operators what is published; this map and the DPIA are
  published with the product.
- **Rights:** the operator serves access, export, rectification and erasure
  for its own node's data with the client's commands; Umanitek serves
  erasure of the curator ledger entry (salt deletion) and answers requests
  about curator decisions at privacy@umanitek.ai. Either party forwards a
  request it cannot serve to the other within 7 days.
- **Contact point for data subjects:** privacy@umanitek.ai.

## 3. Where data physically lives

- Community graph statements: on every subscribed node's replica, wherever
  that node runs (peer-to-peer; no central store).
- Verified graph: on every node's replica; published from the curator node.
- Curator-private files: on the curator node (hosting provider named in the
  current deployment record; updated when it changes).
- Operator-private files: on the operator's machine.

## 4. Cross-border transfers

Replication is global by design; the data replicated is pseudonymous
(wallet addresses) and purpose-limited (threat identifiers). The basis for
any transfer outside the EEA is the operator's explicit consent to publish
into a public network (GDPR art. 49(1)(a)) for the statements, and the
curator's legitimate interest in network security for its reads. Counsel to
confirm.
