"""Test doubles for verified partitions read as triples (KI-288/KI-289).

Since the per-asset triple read replaced the joined partition query, a fake
node answers ``GRAPH <partition> { ?threat ?p ?o }`` pages. Tests keep writing
their fixtures as rows in the joined query's shape; :func:`triples_for_rows`
turns each row into the triples that rebuild it, using the production column
table, so every test that goes through a fake node also checks that the
rows -> triples -> rows round trip is exact.

Usage::

    from _vm_partitions import answer_partition_query, is_partition_query
    if is_partition_query(sparql):
        return answer_partition_query(sparql, {partition_iri: [row, ...]})
"""

import re
from typing import Dict, List

from _blackbox_loader import load_blackbox

_rows = load_blackbox("ruleset.partitions.rows")

_TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
_IDENTIFIER = "http://umanitek.ai/ontology/guardian/identifier"
_GRAPH = re.compile(r"GRAPH <([^>]+)> \{ \?threat \?p \?o \}")
_AFTER = re.compile(r'FILTER\(STR\(\?threat\) > "([^"]*)"\)')
_LIMIT = re.compile(r"LIMIT (\d+)")


def _cell(value):
    return value.get("value") if isinstance(value, dict) else value


def triples_for_rows(rows: List[dict]) -> List[tuple]:
    """The triples a node would hold for these joined-shape rows."""
    triples = []
    for row in rows:
        threat = _cell(row["threat"])
        if row.get("rdfType") is not None:
            triples.append((threat, _TYPE, _cell(row["rdfType"])))
        if row.get("identifier") is not None:
            triples.append((threat, _IDENTIFIER, _cell(row["identifier"])))
        for column, predicates in _rows.COLUMN_PREDICATES.items():
            if row.get(column) is not None:
                triples.append((threat, predicates[0], _cell(row[column])))
    return sorted(set(triples))


def is_partition_query(sparql: str) -> bool:
    return bool(_GRAPH.search(sparql)) and "SELECT ?threat ?p ?o" in sparql


def answer_partition_query(sparql: str, rows_by_partition: Dict[str, List[dict]]) -> List[dict]:
    """One page of the triple query for the partition it names."""
    partition = _GRAPH.search(sparql).group(1)
    after_match = _AFTER.search(sparql)
    after = after_match.group(1) if after_match else ""
    limit = int(_LIMIT.search(sparql).group(1))
    triples = [t for t in triples_for_rows(rows_by_partition.get(partition, [])) if t[0] > after]
    return [{"threat": s, "p": p, "o": o} for s, p, o in triples[:limit]]
