"""Does this host have KVM? Level 4 runs only when it does (proposal §03.5:
level 3–4 hosts need KVM — bare metal or a ``.metal``-class instance).

"The host reports KVM" means more than ``/dev/kvm`` existing: the device opens
read-write for this process (Firecracker's own access check) and answers
``KVM_GET_API_VERSION`` with the stable API version 12. Anything else — no
device, no permission, a device that is not KVM — is a reason, and level 4
does not run. Only a definite yes runs a microVM (LES-011): a check that could
not tell is a no here, because the action it guards is running hostile code.

Usage::

    problem = kvm_problem()          # None when KVM is ready, else why not
    require_kvm()                    # LabConfigError when not (start-up)
"""

from __future__ import annotations

import errno
import fcntl
import os
from pathlib import Path
from typing import Optional

from .config import LabConfigError

KVM_DEVICE = Path("/dev/kvm")
#: ``_IO(KVMIO, 0x00)`` with ``KVMIO = 0xAE`` (linux/kvm.h).
KVM_GET_API_VERSION = 0xAE00
#: The stable KVM API version; it has not changed since Linux 2.6.22.
KVM_API_VERSION = 12


def kvm_problem(device: Optional[Path] = None) -> Optional[str]:
    """None when *device* (default :data:`KVM_DEVICE`) is a usable KVM device; otherwise why it is not."""
    device = device or KVM_DEVICE
    try:
        descriptor = os.open(device, os.O_RDWR | os.O_CLOEXEC)
    except FileNotFoundError:
        return f"{device} does not exist: this host has no KVM (level 4 needs bare metal or a .metal instance)"
    except PermissionError:
        return f"{device} is not readable and writable by this process"
    except OSError as error:
        return f"{device} could not be opened ({errno.errorcode.get(error.errno, error.errno)})"
    try:
        version = fcntl.ioctl(descriptor, KVM_GET_API_VERSION)
    except OSError:
        return f"{device} is not a KVM device"
    finally:
        os.close(descriptor)
    if version != KVM_API_VERSION:
        return f"{device} reports KVM API version {version}, not {KVM_API_VERSION}"
    return None


def require_kvm(device: Optional[Path] = None) -> None:
    """Fail closed at start-up: :class:`LabConfigError` unless KVM is ready."""
    problem = kvm_problem(device)
    if problem is not None:
        raise LabConfigError(f"no level-4 lab without KVM: {problem}")
