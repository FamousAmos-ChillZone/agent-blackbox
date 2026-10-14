# Agent Blackbox

Real-time threat protection for AI agents.

Agent Blackbox checks prompts, tool calls, shell commands, file access, package
installs, and skills against a shared threat graph on the OriginTrail DKG. It
works with Hermes and OpenClaw, runs in audit mode by default, and can block
confirmed threats before they execute.

## Install

Run the installer:

```bash
curl -fsSL blackbox.umanitek.ai | bash
```

The installer sets up an isolated node from the latest official
`@origintrail-official/dkg` npm package and protects detected Hermes and OpenClaw
agents. Docker must be installed and running for its Blazegraph store. The
installer does not replace or modify an existing DKG node.

The default context graph is public, so every Agent Blackbox install can sync
verified threat data immediately. Publishing remains curated so only trusted
data becomes blocking Verifiable Memory. Local working memory and the dashboard
remain available during the initial sync.

## Compatibility

- Hermes 0.21.7 or later is supported (`requires_hermes: ">=0.21.7"`). The
  installer uses a compatible Hermes build.
- OpenClaw 2026.6.11 or later is supported. Older releases do not provide the
  stable plugin hooks Blackbox requires.

Standard Hermes profiles and OpenClaw profiles are attached automatically. A
running OpenClaw Gateway must be restarted once after its plugin config changes.
For a remote or containerized agent, install Blackbox on the Gateway host.

## What Blackbox does on your machine

Read this before installing. Blackbox sends no telemetry or usage data.

- **Checks every action.** Its hooks see each tool call and model request
  before it runs and match them against the threat ruleset locally. In `block`
  mode it refuses matching tool calls; in `audit` mode it only records them.
- **Network calls.**
  - Blackbox's own DKG node keeps a copy of the public verified threat graph
    current, syncing with DKG network peers.
  - **Community sharing is on by default.** Blackbox shares privacy-safe threat
    reports with the open community graph: the threat's name and severity,
    never prompts, commands, file contents or secrets. It also reads other
    nodes' reports, which only ever flag and never block. Turn sharing off with
    `blackbox report --disable-sharing`, the dashboard toggle, or `report: false`
    (`BLACKBOX_REPORT=0`).
  - Package installs are looked up on OSV.dev (`api.osv.dev`): the package name
    and version are sent. Turn this off with `osv_lookup: false`.
  - The optional AI reviewer is off until you set it up. Once on, it sends the
    text your agent reads to the provider you chose (OpenAI or Anthropic).
- **Background processes.**
  - The installer sets up the DKG node (npm package `@origintrail-official/dkg`,
    listening on 127.0.0.1) as a login service, and Blackbox restarts it if it
    stops.
  - `blackbox dashboard` runs a loopback-only web server on 127.0.0.1:9700.
- **Files outside its own folder.** To protect wallets and keys, Blackbox
  matches the paths an agent touches against protected locations: browser
  wallet extension folders, wallet apps, `~/.ssh`, `~/.aws`, `.env` files. To
  locate wallets it reads two small settings files: a Firefox profile's
  `prefs.js` (which add-on lives in which folder) and the Solana CLI's
  `config.yml` (where its keypair is). It never reads wallet contents or keys.
  `blackbox attach` writes Blackbox's plugin entry into the Hermes homes and
  OpenClaw workspaces you choose to protect.
- **Stored credentials.** These live in Blackbox's own folder
  (`$BLACKBOX_HOME`, default `~/.hermes/blackbox`): this node's DKG identity
  and API token, and the reporter signing key (`reporter_key.pem`, mode 0600).
  The AI reviewer's key is saved as the name of the variable that holds it, or
  as itself in `config.yaml` if you paste it. API keys are read only through
  Hermes, never from `.env` files or another program's login.

## Use

```bash
blackbox status       # check Blackbox and DKG health
blackbox sync --wait  # pull the latest threat data now
blackbox dashboard    # open http://127.0.0.1:9700
blackbox attach       # protect all detected local agents
blackbox detach       # remove protection
blackbox chat         # open the Blackbox assistant
```

The installer adds the `blackbox` command to your per-user PATH. It forwards
to `hermes blackbox`, so the longer form remains fully supported.

Blackbox detects:

- prompt injection
- dangerous commands
- vulnerable or malicious dependencies
- sensitive file and secret access
- suspicious skills

Findings are logged locally and shown in the dashboard. In the default `audit`
mode, Blackbox warns without stopping the action. To block confirmed threats,
set the mode to `block` in the dashboard or in `config.yaml`:

```yaml
plugins:
  entries:
    blackbox:
      mode: block
```

## Trader quick start (Trader Shield)

Trader Shield keeps an AI agent away from your crypto wallets and keys. It is opt-in.

1. **Install Blackbox:** `curl -fsSL blackbox.umanitek.ai | bash`, then run `blackbox dashboard`.
2. **Engage Trader Shield:** in the dashboard, open Settings → Trader Shield and switch it on, or use
   the Engage button on the Trader Shield page (`http://127.0.0.1:9700/trader-shield`). Set the
   mode to `block` so wallet threats are stopped, not just flagged.
3. **Choose your wallets** (MetaMask, Phantom, Exodus, Electrum, the Solana CLI) and, optionally,
   list your own public wallet addresses so a raw private key is recognised too. Addresses stay on
   this machine.
4. **Restart your agent** so it picks up the rules.
5. **Try it safely:** in an empty folder run `echo DEMO_KEY=not-a-real-key > .env`, then ask your
   agent to `cat .env`. It is blocked, and the block shows on the dashboard.

The same settings in `config.yaml`:

```yaml
plugins:
  entries:
    blackbox:
      mode: block
      shields:
        trader:
          enabled: true
          wallets: [metamask, phantom, exodus, electrum, solana-cli]
          addresses: []           # your own public addresses (optional)
```

An older config with `wallet_protection`, `protected_wallets` and `wallet_addresses` still
works; the next save from the dashboard moves them under `shields.trader`.

The Trader Shield page lists every attack it was tested against, and what the verified threat
graph already knows about crypto (counted with `scripts/blackbox-trader-graph-counts.py`).

## Community graph (sharing is on by default)

A fresh install shares privacy-safe threat reports with the community graph.
Turning it off is one command and stops sharing on the next action; turning it
back on is one command too.

```bash
blackbox report --disable-sharing       # sharing stops (or report: false / BLACKBOX_REPORT=0)
blackbox report --enable-sharing        # sharing back on
blackbox report --consent               # read the reporter terms
blackbox report --type ioc --ioc-type domain --value evil.example --context fetched-by-tool
blackbox report --status                # what happened to each report, and its community stage
blackbox report --standing              # counted or probation, with a co-sighting estimate
blackbox report --retract IDENTIFIER    # withdraw your own report
blackbox report --false-positive IDENTIFIER --reason tolerable
blackbox report --export FILE           # your key backup + ledger (portable)
blackbox report --erase-identity --confirm
```

A verified rule that blocks here can be demoted to FLAG on this machine only
(audited, never shared; there is no way to raise enforcement locally):

```bash
blackbox rules unblock IDENTIFIER --reason "false positive in our CI"
blackbox rules reblock IDENTIFIER
blackbox rules list
```

Curators run `blackbox curate` (queue, dossier, two-key `propose` /
`approve` / `publish`, `--attest`, `--kill-list`, `outcome`, `graduate`,
`metrics`, `watch`). Community settings in `config.yaml`:
`community_poll_interval` (seconds between pulse probes, 0 off),
`community_keepalive_epoch_days` (re-publish cadence for your own reports,
0 off) and `community_shadow` (compute and log stages, enforce only
monitor). `$BLACKBOX_HOME/allowlist.json` extends the shipped allowlist and
warninglist; `$BLACKBOX_HOME/public_suffix_list.dat` refreshes the vendored
Public Suffix List. The reporter terms, DPIA and controller map ship in
`plugins/blackbox/docs/`.

## How threat data works

Blackbox currently uses one shared graph:

- The **public graph** contains Umanitek-verified threats. These can be blocked
  in block mode. Anyone can read and sync it, while publishing remains curated.
  The UI expands collection contents and lists each threat entity, not one row
  per collection.
- The **community graph** is the open collective-defense layer: any protected
  agent contributes privacy-safe threat reports and learns from other agents'
  reports (aggregated with honest distinct-reporter counts). Community rules
  FLAG only — they can never block. On by default (`report: true`); turn it
  off with `blackbox report --disable-sharing`.

Raw prompts, commands, file contents, secrets, and your local audit trail are
never published — reports carry only deterministic threat names and the
signature fields a reviewer needs, and secret/LLM/custom findings are
hard-excluded from sharing in code. Reports are pseudonymous under your
node's persistent address.

## Configuration

Settings are under `plugins.entries.blackbox` in `config.yaml`. The easiest way
to change them is through the dashboard settings page.

| Setting | Default | Purpose |
|---|---:|---|
| `mode` | `audit` | Warn only (`audit`) or stop confirmed threats (`block`) |
| `block_severity` | `critical` | Minimum severity blocked in block mode |
| `report` | `true` | Share privacy-safe threat reports with the community graph |
| `report_min_severity` | `high` | Minimum severity for heuristic candidates to flag/share |
| `detection.<category>.enabled` | `true` | Enable or disable a detection category |
| `detection.<category>.min_severity` | `info` | Minimum visible severity for a category |
| `protected_paths` | `[]` | Local file globs that always block and are never shared |
| `context_graph_id` | `0x37b1Fdfd…/agent-blackbox-vm` | Public verified threat graph |
| `community_graph_id` | `0x37b1Fdfd…/agent-blackbox-community` | Community graph address; empty keeps sharing dormant |
| `daily_report_limit` | `100` | Daily cap on outbound community reports (cannot be switched off; 0 means the default) |
| `graph_peer_id` | bundled publisher peer | Authoritative threat-data sync source |

Categories are `injection`, `escalation`, `dependency`, `fileaccess`, and
`skill`.

Example:

```yaml
plugins:
  entries:
    blackbox:
      detection:
        dependency:
          enabled: true
          min_severity: critical
        skill:
          enabled: false
      protected_paths:
        - "~/.ssh/*"
        - "**/.env"
```

### Optional AI reviewer

Blackbox can use your configured model for a second opinion on prompt
injection:

```bash
blackbox setup-llm
```

This feature is off by default. It sends reviewed text to the selected model
provider, only warns, and never shares its verdict with the threat graphs.
Disable it with `blackbox setup-llm --disable`.

## Troubleshooting sync

First check the node and retry the sync:

```bash
blackbox status
blackbox sync --wait
```

A first sync can continue in the background for several minutes. If it does not
finish, rerun the command below and include the displayed peer ID and DKG log
when reporting the problem:

```bash
blackbox sync --wait --timeout 180
```
