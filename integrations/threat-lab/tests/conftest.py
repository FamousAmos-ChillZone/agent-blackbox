"""Shared set-up for the threat-lab runner's tests: the runner package on the
path, a digest-pinned config under a temp home, and a recording sandbox."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Callable, Dict, List

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from threat_lab.config import LabConfig  # noqa: E402
from threat_lab.sandbox import SandboxResult, SandboxSpec  # noqa: E402

IMAGE_SHA256 = "e" * 64
IMAGE = f"registry.lab.test/threat-lab-probe@sha256:{IMAGE_SHA256}"


@pytest.fixture
def config(tmp_path) -> LabConfig:
    return LabConfig(home=tmp_path / "lab", image=IMAGE)


class RecordingSandbox:
    """Answers each probe step from *answers* (step name → callable(spec) → SandboxResult)
    and records every spec it was handed, with the work folder's state at the time."""

    def __init__(self, answers: Dict[str, Callable[[SandboxSpec], SandboxResult]]) -> None:
        self.answers = answers
        self.specs: List[SandboxSpec] = []

    def run(self, spec: SandboxSpec) -> SandboxResult:
        self.specs.append(spec)
        return self.answers[spec.probe_args[0]](spec)


def report(payload: dict) -> SandboxResult:
    return SandboxResult(exit_code=0, report=json.dumps(payload).encode("utf-8"))
