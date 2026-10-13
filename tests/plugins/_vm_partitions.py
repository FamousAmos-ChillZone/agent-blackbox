"""Test doubles for the verified graph's small-tier lanes (DKG-lookup B6).

A fake node answers the typed, cursor-paged lanes the refresh reads over
``GRAPH ?g`` under the VM prefix. Tests write their fixtures as rows in the
joined query's shape, keyed by partition; a lane answer is those rows (of the
lane's type, or any row with an identifier for the legacy lane) with their ``g``.

Usage::

    from _vm_partitions import answer_lane_query, is_lane_query
    if is_lane_query(sparql):
        return answer_lane_query(sparql, {partition_iri: [row, ...]})
"""

import re
from typing import Dict, List

_AFTER = re.compile(r'FILTER\(STR\(\?threat\) > "([^"]*)"\)')
_LIMIT = re.compile(r"LIMIT (\d+)")


def _cell(value):
    return value.get("value") if isinstance(value, dict) else value


# --------------------------------------------------------------- small-tier lanes (B6)

_PREFIX = re.compile(r'FILTER\(STRSTARTS\(STR\(\?g\), "([^"]*)"\)\)')
_SIGNAL = re.compile(r"\?threat a defender:(\w+) \.")


def is_lane_query(sparql: str) -> bool:
    """A small-tier lane: a typed (or legacy-identifier) page over ``GRAPH ?g`` under the VM prefix."""
    return "GRAPH ?g {" in sparql and bool(_PREFIX.search(sparql))


def answer_lane_query(sparql: str, rows_by_partition: Dict[str, List[dict]]) -> List[dict]:
    """One page of a lane: the joined-shape rows of the matching type (or any row
    with an identifier for the legacy lane) from every partition under the prefix,
    each with its ``g``, after the cursor, in threat order, up to the limit."""
    prefix = _PREFIX.search(sparql).group(1)
    signal = _SIGNAL.search(sparql)
    wanted_type = f"urn:defender:{signal.group(1)}" if signal else None
    after_match = _AFTER.search(sparql)
    after = after_match.group(1) if after_match else ""
    limit = int(_LIMIT.search(sparql).group(1))
    page = []
    for partition, rows in rows_by_partition.items():
        if not partition.startswith(prefix):
            continue
        for row in rows:
            if wanted_type is None and row.get("identifier") is None:
                continue
            if wanted_type is not None and _cell(row.get("rdfType")) != wanted_type:
                continue
            if _cell(row["threat"]) > after:
                page.append({**row, "g": partition})
    page.sort(key=lambda row: _cell(row["threat"]))
    return page[:limit]


def answer_verified_query(sparql: str, rows_by_partition: Dict[str, List[dict]]) -> List[dict]:
    """The verified read a fake node is asked for (a small-tier lane since B6)."""
    return answer_lane_query(sparql, rows_by_partition)


def is_verified_query(sparql: str) -> bool:
    return is_lane_query(sparql)
