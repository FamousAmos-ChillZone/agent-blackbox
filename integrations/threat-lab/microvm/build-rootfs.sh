#!/usr/bin/env bash
# Build the clean level-4 guest root filesystem and print the --image to pin (run on the lab host).
#
#   integrations/threat-lab/microvm/build-rootfs.sh OUT_DIR KERNEL
#
# KERNEL is a Firecracker guest kernel (uncompressed vmlinux) with virtio block/net and the
# kernel's own IP set-up (CONFIG_IP_PNP): microVMs get their address from the ip= boot argument.
# Writes OUT_DIR/rootfs.ext4 read-only and prints
#   --kernel KERNEL --rootfs OUT_DIR/rootfs.ext4 --image threat-lab-microvm@sha256:<digest>
# Never boot OUT_DIR/rootfs.ext4 itself: the runner boots a fresh copy for every job.
set -euo pipefail

out_dir=${1:?usage: build-rootfs.sh OUT_DIR KERNEL}
kernel=${2:?usage: build-rootfs.sh OUT_DIR KERNEL}
here=$(cd "$(dirname "$0")/.." && pwd)
rootfs="$out_dir/rootfs.ext4"
tree=$(mktemp -d)
container=""
cleanup() {
    if [ -n "$container" ]; then docker rm -f "$container" >/dev/null; fi
    rm -rf "$tree"
}
trap cleanup EXIT

if [ -e "$rootfs" ]; then
    echo "build-rootfs: $rootfs exists; move it away first (images are never overwritten)" >&2
    exit 1
fi
mkdir -p "$out_dir"
docker build -f "$here/microvm/Dockerfile.guest" -t threat-lab-guest "$here"
container=$(docker create threat-lab-guest)
docker export "$container" | tar -x -C "$tree"
# Public resolvers only: the host egress policy drops DNS to any private address.
printf 'nameserver 1.1.1.1\nnameserver 9.9.9.9\n' > "$tree/etc/resolv.conf"
mkfs.ext4 -q -L threatlab -d "$tree" "$rootfs" 2G
chmod 0444 "$rootfs"
digest=$(PYTHONPATH="$here" python3 -c \
    'import sys; from pathlib import Path; from threat_lab.microvm import image_digest; print(image_digest(Path(sys.argv[1]), Path(sys.argv[2])))' \
    "$kernel" "$rootfs")
echo "--kernel $kernel --rootfs $rootfs --image threat-lab-microvm@sha256:$digest"
