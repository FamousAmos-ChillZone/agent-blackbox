# Agent Blackbox — architecture map

This is the map of `plugins/blackbox/`. It must match the disk: the guard
tests in `tests/plugins/test_blackbox_architecture.py` read this file and fail
when a package is missing from it, when a listed path does not exist, or when
code depends on a package its row does not allow. The commit that adds, moves
or re-wires a module updates this file.

Blackbox follows Foreman's structure standard (FMN-V12-STRUCTURE): one module
per feature, one kernel for shared infrastructure, dependencies pointing one
way, and every package used only through its public entry (`__init__.py`).

## The four flows

1. **SYNC (down)** — `sync` keeps the local DKG node's copy of Umanitek's
   verified threat graph current; `ruleset` compiles what the node holds into
   O(1) lookups.
2. **CHECK (hot path)** — `guard` intercepts every tool call and model request;
   `detection` matches it against the ruleset (pure, microseconds, fail-open).
3. **RECORD (local)** — `audit` keeps redacted, size-capped logs on this
   machine; `dashboard` renders them.
4. **REPORT (up)** — `community` decides what may leave the machine, builds
   privacy-safe reports, and reads what other nodes reported.

## Modules

| Module | Owns | Entry | May depend on |
|---|---|---|---|
| `kernel` | constants + ontology IRIs, config and settings, the DKG HTTP client, threat identifiers, RDF terms, SPARQL escaping, YAML files, terminal-safe display, this node's identity, secret redaction | `kernel/__init__.py` (each kernel module is public) | — |
| `attach` | finding Hermes homes and OpenClaw workspaces, copying the plugin in, enabling/disabling it; `blackbox attach` / `detach` | `attach/__init__.py` | `kernel` |
| `detection` | the pure detectors, action parsing, content scanners, escalation shapes, OSV lookups, the LLM reviewer; `blackbox setup-llm` | `detection/__init__.py` | `kernel`, `attach` |
| `audit` | local findings / activity logs, redaction, the private audit record, the outbound share ledger + cooldown + daily cap | `audit/__init__.py` | `kernel` |
| `community` | the outbound share gate and send, report quads, reading + aggregating community reports, graph-wide statistics for the dashboard; `blackbox report` | `community/__init__.py` | `kernel`, `audit`, `detection` (the closed report vocabularies) |
| `ruleset` | SPARQL reads of the verified graph, compiling rows into the `Ruleset`, disk + memory cache, cross-process refresh lock, merging the community tier | `ruleset/__init__.py` | `kernel`, `community` |
| `sync` | the local node's catch-up of the verified graph, the managed DKG node process, sync state + progress bookmarks; `blackbox sync` | `sync/__init__.py` | `kernel`, `ruleset`, `community` |
| `guard` | the five Hermes hooks, filtering + recording + sharing findings, per-session context, background OSV / LLM / auto-attach work | `guard/__init__.py` | `kernel`, `attach`, `audit`, `community`, `detection`, `ruleset` |
| `chat` | `blackbox chat` — the managed Blackbox assistant profile | `chat/__init__.py` | `kernel`, `attach` |
| `dashboard` | the local web UI (FastAPI, loopback-only) and its static assets; `blackbox dashboard` | `dashboard/__init__.py` | `kernel`, `attach`, `audit`, `community`, `ruleset`, `sync` |
| `curate` | the curator node's tooling (Community Graph Refine, item R6); today only unused catalog-import helpers | `curate/__init__.py` | `kernel` |

## Root (the composition layer — Hermes' plugin layout, kept thin)

| File | Role |
|---|---|
| `plugin.yaml` | Hermes plugin manifest (hooks list, eager `backend` load). |
| `__init__.py` | `register(ctx)`: wires the `guard` hooks and the `blackbox` CLI. May depend on `cli`, `guard`, `kernel`. |
| `cli.py` | The `blackbox` argument parser and dispatch, plus `status`. May depend on every module. |
| `README.md` | Operator-facing plugin readme. |

## Rules

- **One way.** A module depends only on the modules in its row. The kernel
  depends on nothing in the plugin. No cycles.
- **Through the entry.** Code outside a package imports the package, or a
  name / submodule listed in its `__all__` — never its internals
  (`from ..community.reader import …` is a violation). Kernel modules are all
  public. Tests may reach internals; plugin code may not.
- **Size.** A file over ~400 lines or a folder over 15 files is split. Files
  and functions (over ~50 lines) that were already over when the guard landed
  are listed in `tests/plugins/architecture_baseline.json` and may only shrink
  — lower the number in the same commit that shrinks them.
- **Lazy imports count.** Every relative import, including ones inside
  functions, must resolve (a broken lazy import fails silently behind the
  fail-open hooks — FIX-0017).
- **Moves are refactors.** Moving code between modules is its own commit with
  the suite green, never mixed with behaviour changes.

## Installed layout

`attach` copies this whole folder into each agent home
(`~/.hermes/plugins/blackbox/`) minus caches and tests, plus the OpenClaw JS
bridge bundled under `_openclaw/` (built at install time, not in the repo).
