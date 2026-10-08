"""Ladder — the reporter ladder runs itself (Community Curation C6).

A reporter climbs from probation to established on curator-confirmed NOVEL
reports. Before this package a curator typed one command per report to credit
it, so nobody could ever graduate.

* :mod:`.novelty_facts` — gathers, from the public record, the facts the
  novelty rule judges (``community.reputation.novelty_credit``).
* :mod:`.outcomes` — credits every reporter of a threat when the acting
  authority's verdict on it is published, exactly once, and keeps the private
  ledger's bands in step with the published trusted-reporter list. Any curator
  node can run it over the whole public record and reach the same ledger.

Import the submodule you need; this package imports nothing itself.
"""
