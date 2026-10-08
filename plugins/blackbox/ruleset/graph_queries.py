"""SPARQL builders for reading the VERIFIED threat graph.

Pure string builders — no I/O. Every untrusted value that reaches a query goes
through :func:`..kernel.sparql_text.sparql_string_literal`; IRIs are checked against
``_FORBIDDEN_IRI_CHARS``. Used by :mod:`.fetching` (paged reads) and
:mod:`.compiler` (legacy proof reads).
"""

from __future__ import annotations

import json
import re

_SELECT_COLUMNS = """?threat ?rdfType ?identifier ?severity ?name ?description
       ?pattern ?toolName ?argShape ?packageName ?packageVersion
       ?packageEcosystem ?advisoryId ?curated ?category ?skillName
       ?skillVersion ?dangerShape ?kind ?iocValue ?targetSubject
       ?correctionAction ?canonicalType ?observationCategory
       ?lifecycleStatus ?normalizedValue ?provenanceJson ?sourceId"""

_DEFENDER_PREFIXES = """PREFIX defender: <urn:defender:>
PREFIX dp: <urn:defender:p:>
PREFIX blackbox: <urn:blackbox:>
PREFIX bp: <urn:blackbox:p:>
PREFIX schema: <http://schema.org/>
"""
_VM_PARTITION_QUERY_LIMIT = 50_000
_FORBIDDEN_IRI_CHARS = frozenset('<>"{}|^`\\\r\n\t')
#: A wallet-namespaced graph id starts with its owner's address (lowercased here).
_WALLET_ADDRESS = re.compile(r"0x[0-9a-f]{40}")


def _threat_cursor_filter(after: str) -> str:
    if not after:
        return ""
    return f"FILTER(STR(?threat) > {json.dumps(after, ensure_ascii=True)})"


def _defender_page_sparql(
    signal_type: str,
    properties: str,
    limit: int,
    after: str,
    graph_uri: str = "",
) -> str:
    cursor_filter = _threat_cursor_filter(after)
    body = f"""    {{
        SELECT ?threat WHERE {{
            ?threat a defender:{signal_type} .
            {cursor_filter}
        }}
        ORDER BY STR(?threat)
        LIMIT {int(limit)}
    }}
    BIND(defender:{signal_type} AS ?rdfType)
{properties}"""
    if graph_uri:
        body = f"  GRAPH <{graph_uri}> {{\n{body}\n  }}"
    return f"""{_DEFENDER_PREFIXES}
SELECT DISTINCT {_SELECT_COLUMNS}
WHERE {{
{body}
}}
ORDER BY STR(?threat)
"""


def _source_observations_sparql(
    limit: int,
    after: str = "",
    graph_uri: str = "",
) -> str:
    """Fetch compact IOC observations without pulling citation triples."""
    cursor_filter = _threat_cursor_filter(after)
    body = f"""    {{
        SELECT ?threat WHERE {{
            ?threat a blackbox:SourceObservation .
            {cursor_filter}
        }}
        ORDER BY STR(?threat)
        LIMIT {int(limit)}
    }}
    BIND(blackbox:SourceObservation AS ?rdfType)
    OPTIONAL {{ ?threat bp:canonicalType ?canonicalType . }}
    OPTIONAL {{ ?threat bp:category ?observationCategory . }}
    OPTIONAL {{ ?threat bp:lifecycleStatus ?lifecycleStatus . }}
    OPTIONAL {{ ?threat bp:normalizedValue ?normalizedValue . }}
    OPTIONAL {{ ?threat bp:provenanceJson ?provenanceJson . }}
    OPTIONAL {{ ?threat bp:sourceId ?sourceId . }}"""
    if graph_uri:
        body = f"  GRAPH <{graph_uri}> {{\n{body}\n  }}"
    return f"""{_DEFENDER_PREFIXES}
SELECT DISTINCT {_SELECT_COLUMNS}
WHERE {{
{body}
}}
ORDER BY STR(?threat)
"""


def _threats_sparql(limit: int, after: str = "", graph_uri: str = "") -> str:
    return _defender_page_sparql(
        "DependencySignal",
        """    OPTIONAL { ?threat dp:kind ?kind . }
    OPTIONAL { ?threat dp:severity ?severity . }
    OPTIONAL { ?threat schema:name ?name . }
    OPTIONAL { ?threat schema:description ?description . }
    OPTIONAL { ?threat dp:package ?packageName . }
    OPTIONAL { ?threat dp:version ?packageVersion . }
    OPTIONAL { ?threat dp:ecosystem ?packageEcosystem . }
    OPTIONAL { ?threat dp:advisoryId ?advisoryId . }""",
        limit,
        after,
        graph_uri,
    )


def _defender_threats_sparql(
    limit: int,
    after: str = "",
    graph_uri: str = "",
) -> tuple:
    return (
        _threats_sparql(limit, after, graph_uri),
        _defender_page_sparql(
            "InjectionSignal",
            """    OPTIONAL { ?threat dp:kind ?kind . }
    OPTIONAL { ?threat dp:severity ?severity . }
    OPTIONAL { ?threat schema:name ?name . }
    OPTIONAL { ?threat schema:description ?description . }
    OPTIONAL { ?threat dp:pattern ?pattern . }""",
            limit,
            after,
            graph_uri,
        ),
        _defender_page_sparql(
            "SkillSignal",
            """    OPTIONAL { ?threat dp:kind ?kind . }
    OPTIONAL { ?threat dp:severity ?severity . }
    OPTIONAL { ?threat schema:name ?name . }
    OPTIONAL { ?threat schema:description ?description . }""",
            limit,
            after,
            graph_uri,
        ),
        _defender_page_sparql(
            "IocSignal",
            """    OPTIONAL { ?threat dp:kind ?kind . }
    OPTIONAL { ?threat dp:severity ?severity . }
    OPTIONAL { ?threat schema:name ?name . }
    OPTIONAL { ?threat schema:description ?description . }
    OPTIONAL { ?threat dp:iocType ?category . }
    OPTIONAL { ?threat dp:value ?iocValue . }""",
            limit,
            after,
            graph_uri,
        ),
        _defender_page_sparql(
            "CorrectionSignal",
            """    OPTIONAL { ?threat dp:targetSubject ?targetSubject . }
    OPTIONAL { ?threat dp:action ?correctionAction . }""",
            limit,
            after,
            graph_uri,
        ),
        _source_observations_sparql(limit, after, graph_uri),
    )


def _legacy_threats_sparql(
    limit: int,
    after: str = "",
    graph_uri: str = "",
) -> str:
    cursor_filter = _threat_cursor_filter(after)
    body = f"""  {{
    SELECT ?threat WHERE {{
      ?threat g:identifier ?cursorIdentifier .
      {cursor_filter}
    }}
    ORDER BY STR(?threat)
    LIMIT {int(limit)}
  }}
  ?threat g:identifier ?identifier .
  OPTIONAL {{ ?threat a ?rdfType . }}
  OPTIONAL {{ ?threat g:kind ?kind . }}
  OPTIONAL {{ ?threat g:severity ?severity . }}
  OPTIONAL {{ ?threat schema:name ?name . }}
  OPTIONAL {{ ?threat schema:description ?description . }}
  OPTIONAL {{ ?threat g:pattern ?pattern . }}
  OPTIONAL {{ ?threat g:toolName ?toolName . }}
  OPTIONAL {{ ?threat g:argShape ?argShape . }}
  OPTIONAL {{ ?threat g:packageName ?packageName . }}
  OPTIONAL {{ ?threat g:packageVersion ?packageVersion . }}
  OPTIONAL {{ ?threat g:packageEcosystem ?packageEcosystem . }}
  OPTIONAL {{ ?threat schema:identifier ?advisoryId . }}
  OPTIONAL {{ ?threat g:curated ?curated . }}
  OPTIONAL {{ ?threat g:category ?category . }}
  OPTIONAL {{ ?threat g:skillName ?skillName . }}
  OPTIONAL {{ ?threat g:skillVersion ?skillVersion . }}
  OPTIONAL {{ ?threat g:dangerShape ?dangerShape . }}"""
    if graph_uri:
        body = f"  GRAPH <{graph_uri}> {{\n{body}\n  }}"
    return f"""PREFIX g: <http://umanitek.ai/ontology/guardian/>
PREFIX schema: <http://schema.org/>
SELECT DISTINCT {_SELECT_COLUMNS}
WHERE {{
{body}
}}
ORDER BY STR(?threat)
"""


def _context_graph_data_uri(cg_id: str) -> str:
    value = str(cg_id or "").strip()
    if not value or any(char in value for char in _FORBIDDEN_IRI_CHARS):
        return ""
    return f"did:dkg:context-graph:{value}"


def _verified_partitions_sparql(cg_id: str) -> str:
    """The verified graph's VM assertion graphs, PINNED to the graph owner.

    KI-106 (Refine R0): any authorized publisher can write the verified
    graph, so only assets whose on-chain UAL sits in the owner's namespace
    (``did:dkg:<chain>/<owner>/<id>`` — the ``0x…`` prefix of a
    wallet-namespaced graph id) are read. Bench-checked 2026-10-01 on a
    mainnet node: all 178 verified assets carry the owner segment and no
    attribution predicate, so this is the key the data actually has. A graph
    id that is not wallet-namespaced is not pinned. (Pull-synced metadata is
    responder-asserted; the cryptographic pin is R7a's signed envelope.)
    """
    data_graph = _context_graph_data_uri(cg_id)
    if not data_graph:
        return ""
    vm_prefix = f"{data_graph}/_verifiable_memory/"
    pin = _owner_pin(cg_id)
    return f"""PREFIX dkg: <http://dkg.io/ontology/>
SELECT DISTINCT ?assertionGraph ?status WHERE {{
  GRAPH <{data_graph}/_meta> {{
    ?ka dkg:assertionGraph ?assertionGraph .
{pin}    OPTIONAL {{ ?ka dkg:status ?status . }}
  }}
  FILTER(STRSTARTS(STR(?assertionGraph), {json.dumps(vm_prefix)}))
}}
ORDER BY ?assertionGraph
"""


def _owner_pin(cg_id: str) -> str:
    """The KI-106 owner pin as SPARQL lines (empty for a graph id that is not
    wallet-namespaced) — shared by every read of the verified graph's _meta."""
    owner = str(cg_id).split("/", 1)[0].lower()
    if not _WALLET_ADDRESS.fullmatch(owner):
        return ""
    return f"    ?ka dkg:kaUal ?kaUal .\n    FILTER(CONTAINS(LCASE(STR(?kaUal)), {json.dumps('/' + owner + '/')}))\n"


def _verified_partition_totals_sparql(cg_id: str) -> str:
    """ONE aggregate row: how many verified assets this node holds CONFIRMED,
    and their public triple count — for the dashboard's sync meter.

    Same owner pin and prefix as :func:`_verified_partitions_sparql`; bounded
    by construction (an aggregate, no listing — LES-013). The node's _meta
    holds only assets it has already downloaded, so this is "downloaded",
    never the graph's full size (that comes from the node's recovery backlog).
    """
    data_graph = _context_graph_data_uri(cg_id)
    if not data_graph:
        return ""
    vm_prefix = f"{data_graph}/_verifiable_memory/"
    return f"""PREFIX dkg: <http://dkg.io/ontology/>
SELECT (COUNT(DISTINCT ?ka) AS ?assets) (SUM(?publicTriples) AS ?triples) WHERE {{
  GRAPH <{data_graph}/_meta> {{
    ?ka dkg:assertionGraph ?assertionGraph ;
        dkg:status ?status .
{_owner_pin(cg_id)}    OPTIONAL {{ ?ka dkg:publicTripleCount ?publicTriples . }}
  }}
  FILTER(STR(?status) = "confirmed")
  FILTER(STRSTARTS(STR(?assertionGraph), {json.dumps(vm_prefix)}))
}}
"""


def _partition_triples_sparql(graph_uri: str, *, after: str = "", limit: int = _VM_PARTITION_QUERY_LIMIT) -> str:
    """Every triple of ONE verified partition, in threat order, after a cursor.

    A plain scan of one asset's named graph — no joins, no DISTINCT, no OFFSET.
    The joined query this replaces (one row per threat with ~27 OPTIONAL
    columns over five partitions) exceeded DKG 10.0.21's 30 s store deadline on
    a single asset even on a calm node, while this read returns the largest
    asset (15,032 triples) in 1.7 s (KI-288/KI-289, bench v21 2026-10-06).
    :mod:`.partitions` rebuilds the same rows from the triples.
    """
    return f"""SELECT ?threat ?p ?o
WHERE {{
  GRAPH <{graph_uri}> {{ ?threat ?p ?o }}
  {_threat_cursor_filter(after)}
}}
ORDER BY STR(?threat) ?p ?o
LIMIT {int(limit)}
"""


def _partition_triple_count_sparql(graph_uri: str) -> str:
    """How many triples ONE verified partition holds — the check a read is held to.

    A DKG node whose store is restarting answers queries with zero rows rather
    than an error (bench native-c, 2026-10-06), so a read alone cannot tell an
    empty or cut-short answer from the real content.
    """
    return f"SELECT (COUNT(*) AS ?n) WHERE {{ GRAPH <{graph_uri}> {{ ?threat ?p ?o }} }}"


# ---------------------------------------------------------------------------
# Legacy proof verification (backward compatibility)
# ---------------------------------------------------------------------------

# This fallback keeps already-published proof-era rows effective.
_PROOFS_SPARQL = """PREFIX g: <http://umanitek.ai/ontology/guardian/>
SELECT ?proof ?root ?member WHERE {
  ?proof a g:CurationProof .
  ?proof g:anchorRoot ?root .
  ?proof g:anchorMember ?member .
}"""
