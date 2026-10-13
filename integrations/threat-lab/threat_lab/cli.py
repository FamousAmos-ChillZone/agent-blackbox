"""``python -m threat_lab <command>`` — the lab runner's own CLI.

* ``serve --image <name@sha256:…> [--host 127.0.0.1] [--port 8790] [--home DIR]``
  — the job API on loopback (the SSH tunnel's end), sweeping old artifacts at
  start-up and daily.

``serve`` and ``run`` start only when the host egress policy (``egress.nft``)
is loaded and the lab network sits on the bridge it guards (fail closed); every
networked probe is then watched against its caps (:mod:`threat_lab.egress`).
* ``run --image … --level {1,2,4} --key KEY --identifier ID`` — one job,
  printing ``{"state", "output"}`` as JSON (an operator's check on the lab host).

``serve``/``run`` with ``--kernel K --rootfs R`` make a Firecracker lab (level 4
only; ``--image`` is then ``<name>@sha256:<image_digest(K, R)>``). They start
only when the host reports KVM (:mod:`threat_lab.kvm`), the kernel and rootfs
hash to the pinned image, and the lab bridge exists (fail closed).
* ``sweep [--home DIR]`` — delete raw artifacts older than 90 days.
* ``fixtures --write`` — regenerate the raw-output fixtures (see :mod:`threat_lab.fixtures`).
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import threading
from pathlib import Path
from typing import List, Optional

from .artifacts import ArtifactStore
from .config import LAB_LEVELS, LabConfig, LabConfigError, MicroVMSettings
from .egress import NftablesEgressGuard
from .kvm import require_kvm
from .sandbox import GVisorSandbox, Sandbox

DEFAULT_HOME = Path("/var/lib/threat-lab")
DEFAULT_PORT = 8790
_SWEEP_INTERVAL_SECONDS = 86_400


def main(argv: Optional[List[str]] = None) -> int:
    args = _parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    try:
        return args.command(args)
    except LabConfigError as error:
        print(f"threat-lab: {error}", file=sys.stderr)
        return 2


def _serve(args: argparse.Namespace) -> int:
    from .api import WORKERS, JobBoard, check_loopback, make_server
    from .runner import LabRunner

    check_loopback(args.host)
    config = _config(args)
    egress = _loaded_egress(config)
    egress.reset()
    artifacts = ArtifactStore(config.artifacts_dir)
    _sweep_daily(artifacts)
    workers = config.microvm.slots if config.microvm else WORKERS     # one microVM per worker
    board = JobBoard(config, LabRunner(config, _sandbox(config, egress), artifacts), workers=workers)
    server = make_server(board, args.host, args.port)
    logging.getLogger("threat_lab").info("listening on %s:%s", args.host, args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        board.shutdown()
    return 0


def _run(args: argparse.Namespace) -> int:
    from .runner import JobRequest, LabRunner

    config = _config(args)
    # No reset here: a running `serve` may be watching sandboxes in those sets.
    runner = LabRunner(config, _sandbox(config, _loaded_egress(config)), ArtifactStore(config.artifacts_dir))
    result = runner.run(JobRequest(args.key, args.identifier, args.level))
    print(json.dumps({"state": result.state, "output": result.output}, sort_keys=True))
    return 0


def _config(args: argparse.Namespace) -> LabConfig:
    """A gVisor lab, or — with ``--kernel``/``--rootfs`` — a Firecracker lab,
    which is refused unless the host reports KVM and the image files hash to ``--image``."""
    if (args.kernel is None) != (args.rootfs is None):
        raise LabConfigError("a microVM lab needs both --kernel and --rootfs")
    if args.kernel is None:
        return LabConfig(home=args.home, image=args.image)
    require_kvm()
    from .microvm import check_image

    config = LabConfig(home=args.home, image=args.image, microvm=MicroVMSettings(kernel=args.kernel, rootfs=args.rootfs))
    check_image(config)
    return config


def _sandbox(config: LabConfig, egress: NftablesEgressGuard) -> Sandbox:
    if config.microvm is None:
        return GVisorSandbox(config, egress)
    from .microvm import FirecrackerSandbox

    return FirecrackerSandbox(config, egress)


def _loaded_egress(config: LabConfig) -> NftablesEgressGuard:
    egress = NftablesEgressGuard()
    egress.check_loaded(config.docker, None if config.microvm else config.network)
    return egress


def _sweep(args: argparse.Namespace) -> int:
    deleted = ArtifactStore(args.home / "artifacts").sweep()
    print(json.dumps({"deleted": len(deleted)}))
    return 0


def _fixtures(args: argparse.Namespace) -> int:
    from .fixtures import build_fixtures, write_fixtures

    if args.write:
        write_fixtures()
    else:
        sys.stdout.write("".join(build_fixtures().values()))
    return 0


def _sweep_daily(artifacts: ArtifactStore) -> None:
    def tick() -> None:
        deleted = artifacts.sweep()
        logging.getLogger("threat_lab.artifacts").info("retention sweep deleted %d artifacts", len(deleted))
        timer = threading.Timer(_SWEEP_INTERVAL_SECONDS, tick)
        timer.daemon = True
        timer.start()

    tick()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="threat-lab", description="Threat lab runner (levels 1-2 in gVisor, 4 in Firecracker).")
    commands = parser.add_subparsers(required=True)

    serve = commands.add_parser("serve", help="the job API on loopback")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=DEFAULT_PORT)
    serve.set_defaults(command=_serve)

    run = commands.add_parser("run", help="run one job and print its outcome")
    run.add_argument("--level", type=int, choices=LAB_LEVELS, required=True)
    run.add_argument("--key", required=True, help="the curator's job key")
    run.add_argument("--identifier", required=True)
    run.set_defaults(command=_run)

    sweep = commands.add_parser("sweep", help="delete raw artifacts older than 90 days")
    sweep.set_defaults(command=_sweep)

    fixtures = commands.add_parser("fixtures", help="print or --write the raw-output fixtures")
    fixtures.add_argument("--write", action="store_true")
    fixtures.set_defaults(command=_fixtures)

    for command in (serve, run, sweep):
        command.add_argument("--home", type=Path, default=DEFAULT_HOME)
    for command in (serve, run):
        command.add_argument("--image", required=True, help="the sandbox image, pinned name@sha256:<hex>")
        command.add_argument("--kernel", type=Path, help="a Firecracker lab: the guest kernel (needs KVM)")
        command.add_argument("--rootfs", type=Path, help="a Firecracker lab: the clean guest root filesystem")
    return parser
