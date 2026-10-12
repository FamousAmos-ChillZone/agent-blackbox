# Threat lab runner (levels 1–2 in gVisor, level 4 in Firecracker)

The lab half of the trust-and-threat lab (proposal §03.5). A separate deployable,
**not plugin code** (D28): the curator's `LabController` (`plugins/blackbox/curate/lab/`)
talks to it over an SSH tunnel; this runner tests what it is asked to and answers with
the raw output the curator's Evidence Extractor reads. **The lab never builds Evidence**:
only `plugins/blackbox/curate/lab/extractor.py` does, so the lab reports what it saw and
never decides what that means.

| Level | What it does | Sandbox |
|---|---|---|
| 1 look | unauthenticated look-ups only: DNS + TLS certificate, public registry record, public wallet history | gVisor (`runsc`), default netstack, lab network |
| 2 read | download the package / skill file, then read it with deterministic rules (install hooks, obfuscation, embedded IOCs) — never run | download: gVisor with network · read: `--network=none`, download mounted read-only |
| 4 run | install a package (`npm install` / `pip install`, scripts on) or run a skill file, with inert bait planted; traffic recorded on the host | a fresh Firecracker microVM per job, on a KVM host (Lab 2) |

A runner is either Lab 1 (levels 1–2) or Lab 2 (level 4): `--kernel`/`--rootfs` make it Lab 2.

Every probe runs in a fresh container from the clean read-only image (`--rm`), with CPU,
memory (no swap), pid and wall-clock caps. A probe past its job's deadline is killed by
container name and the run is done with the note `deadline-reached` alone; one killed by
its memory cap with `resource-cap-reached` alone. The curator's Evidence then answers no
check: **could-not-tell**, with no retry. A probe that gives no readable report is a broken
lab: the run is `failed` and the curator submits it again (at most 3 runs a job).

## Rules it keeps

- **Loopback only.** `serve` refuses any address that is not a loopback IP literal
  (even `localhost`), before binding. The lab is not on Tailscale.
- **No keys, wallet or credentials.** Nothing here signs; the curator signs evidence.
- **No personal data kept.** URL query strings, fragments and user names/passwords are
  stripped at the API boundary, before anything is stored, logged or probed (F-023).
- **Raw artifacts stay here**, under `<home>/artifacts/<sha256>`, for 90 days, then the
  retention sweep deletes them (at start-up, daily, or `threat-lab sweep`). Curators get
  the job's output only — hosts, sha256 digests and note codes; no page text.
- **One schema, no copy.** The runner imports nothing from `plugins.blackbox`; it loads
  exactly one plugin file by path, `plugins/blackbox/curate/lab/evidence_schema.py`
  (`threat_lab/schema.py`). On the lab host deploy that file beside the runner and set
  `THREAT_LAB_EVIDENCE_SCHEMA=/path/to/evidence_schema.py`.

## Host egress policy (LR2)

`egress.nft` is loaded on the lab HOST, on the host side of the lab bridge — never inside a
sandbox, where a sample could remove it:

- out: TCP 80/443 (a new connection must open with a plain SYN) and UDP 53; nothing else —
  no ICMP, no raw IP, no IPv6 (sandboxes also run with `--cap-drop=ALL`, so no NET_RAW);
- never: the lab host (any of its addresses), another sandbox, private and reserved ranges,
  169.254.169.254;
- caps per sandbox address: 10 new connections a second (burst 20) and 30 new destinations a
  minute (burst 30). The first packet over either cap puts the address in the `offenders`
  set and every later packet from it is dropped. The runner watches that set while a networked
  probe runs (`threat_lab/egress.py`), kills the sandbox, logs the kill against its job, and
  the run is done with the note `scanning-killed` alone — the kill is itself the evidence.

The host's upstream DNS resolvers must be public addresses: a private resolver is a private
range and is blocked. `serve` and `run` refuse to start (fail closed) unless the policy is
loaded, br_netfilter is on, and the lab network sits on the guarded bridge:

```
nft -f integrations/threat-lab/egress.nft            # as root; replaces only `inet threat_lab`
modprobe br_netfilter && sysctl net.bridge.bridge-nf-call-iptables=1
docker network create -o com.docker.network.bridge.name=threatlab0 \
    -o com.docker.network.bridge.enable_icc=false threat-lab
```

The runner runs as root on the lab host (it reads and clears `nft` sets), and `serve` empties the
per-address sets at start-up so a new sandbox never inherits a dead one's offence.

## Run

```
docker build -t threat-lab-probe integrations/threat-lab      # the sandbox image (see Dockerfile)
cd integrations/threat-lab
python -m threat_lab serve --image <name>@sha256:<hex> --home /var/lib/threat-lab   # 127.0.0.1:8790
python -m threat_lab run --image … --level 2 --key <key> --identifier dep:npm:left-pad@1.3.0
python -m threat_lab sweep --home /var/lib/threat-lab
python -m threat_lab fixtures --write     # after any rules / output change
```

API — exactly what the curator's `LabTransport` calls (`curate/lab/transport.py`):

| Route | Answer |
|---|---|
| `POST /jobs {"key","identifier","level"}` | 202 `{"key"}` |
| `GET /jobs/<key>` | `{"key","state"}`, state `queued` · `running` · `done` · `failed` |
| `GET /jobs/<key>/output` | the raw output (`threat_lab/output.py`) once done; 409 before; 404 unknown |
| `GET /health` | `{"image_sha256","levels","open_jobs"}` |

The key is the curator's `<sha256(query-stripped identifier)>:<level>:<image sha256>`; a
key for another image is refused (409). A known job is never run twice, except a `failed`
one submitted again (the curator's retry). 500 open jobs at most; a full board answers 503
and the curator asks again later.

## Level 4: Firecracker microVMs (LR3)

Lab 2 is a KVM host (bare metal or a `.metal` instance). Each job boots a **fresh copy of the
clean image** — never a snapshot: restoring one snapshot more than once is documented insecure
(duplicated entropy, ids, tokens), and Firecracker loads snapshots only through its API socket,
so every microVM starts with `--no-api --config-file` (asserted before every boot). The copy is
hashed and compared with the pinned `--image` before it boots, and deleted with the job.

- **KVM or nothing.** `serve`/`run` refuse to start a level-4 lab unless `/dev/kvm` opens
  read-write and answers the KVM API version (`threat_lab/kvm.py`); every boot checks again,
  and a job on a host that lost KVM is not run (`failed`).
- **One microVM per worker, two at once** (`MicroVMSettings.slots`, 2 on a 4-vCPU / 16 GB host);
  a third job waits `queued`. Slot *n*'s guest is `172.30.4.(10+n)` on the lab bridge.
- **5-minute deadline**: the lab kills a run at 280 s (inside the curator's 300 s) →
  `deadline-reached` → could-not-tell.
- **Jailed**: Firecracker runs under `jailer` (chroot, uid/gid 65534, cgroup v2 memory cap).
- **Network**: each microVM's TAP joins the lab bridge `threatlab0`, so the LR2 egress policy
  applies to every packet; the host records the TAP with `tcpdump` (`threat_lab/traffic.py`
  reads it: DNS names, TLS server names, unexplained addresses, bait seen leaving). The capture
  is kept as a raw artifact for 90 days.
- **Inside the guest** (`threat_lab/guest.py`, run by `microvm/init.sh`): the job comes in on a
  read-only drive; the install or skill runs as an unprivileged user under root's `strace -ff`;
  only processes the package's own code started are reported (npm lifecycle shells, pip's build
  backend, all of a skill); the report goes out on a raw root-only drive; the guest reboots.
- **Bait** (`threat_lab/bait.py`): credentials valid nowhere and a zero-funds wallet, all marked
  `TLBAIT` or derived from a published seed — the only data a sample can take.
- **Not built here:** prompt injection against a test agent. A test agent needs a model inside
  the guest and the lab holds no keys; it waits for its own item. A browser per microVM is built
  only if urlscan.io proves insufficient (D22).

Host set-up (as root), after the LR2 policy:

```
ip link add threatlab0 type bridge && ip addr add 172.30.4.1/24 dev threatlab0 && ip link set threatlab0 up
iptables -t nat -A POSTROUTING -s 172.30.4.0/24 ! -o threatlab0 -j MASQUERADE   # or the nft equivalent
modprobe br_netfilter && sysctl net.bridge.bridge-nf-call-iptables=1
integrations/threat-lab/microvm/build-rootfs.sh /srv/threat-lab/image /srv/threat-lab/vmlinux
python -m threat_lab serve --home /var/lib/threat-lab --kernel … --rootfs … --image threat-lab-microvm@sha256:…
```

`jailer`, `firecracker`, `tcpdump` and `ip` must be on PATH; cgroup v2 with the memory
controller enabled for the jailer's cgroups. Level 4 starts only after Umanitek's legal
sign-off (§03.5 ground rules).

## Tests

```
python -m pytest integrations/threat-lab/tests
```

They need neither Docker, gVisor, KVM nor Firecracker: the sandboxes' kill paths run against
stand-in `docker`, `nft`, `jailer`, `ip` and `tcpdump` executables. `test_the_ruleset_parses_with_nft` runs `nft -c -f egress.nft` and
skips with its reason when nft is absent or not permitted (run the suite as root on the lab
host). On the lab host, also run
`THREAT_LAB_IMAGE=<name>@sha256:<hex> pytest -m integration tests/integration/test_blackbox_lab_egress.py`:
a real scanning sample is killed and noted, and a real sandbox reaches neither the private
ranges, the metadata address nor the host. On the KVM host, `tests/integration/test_blackbox_lab_microvm.py`
(its environment variables are in its docstring) boots real microVMs: image-only boot, the
deadline kill, two at once and a third waiting, and a recorded install of a known `MAL-` package. The fixture output under `tests/fixtures/*_output.json` is checked from
the curator side by `tests/plugins/test_blackbox_lab_evidence.py`, which feeds it through the
canonical extractor and pins the result in `*_evidence.json` (regenerate with
`python -m tests.plugins.test_blackbox_lab_evidence --write` from the repo root). That file
also drives this runner's server with the real `LabTransport`.
