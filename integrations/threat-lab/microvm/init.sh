#!/bin/sh
# PID 1 inside each level-4 microVM (the kernel's init=, set by threat_lab/microvm.py).
# Mounts what the guest needs, then hands over to the job runner, which writes its report
# to the report drive and reboots — and a reboot ends Firecracker (boot arg reboot=k).
# If the runner ever exits instead, PID 1 ends, the kernel panics and panic=1 reboots it.
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs -o mode=0755 tmpfs /run
mount -t tmpfs -o mode=1777 tmpfs /tmp
exec env -i PATH=/usr/local/bin:/usr/bin:/bin PYTHONPATH=/opt/threat-lab PYTHONDONTWRITEBYTECODE=1 \
    python3 -m threat_lab.guest
