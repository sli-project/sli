#!/bin/bash
set -euo pipefail

case "$(/usr/bin/systemd-detect-virt --vm)" in
    qemu|kvm) ;;
    *) exit 1 ;;
esac
[[ $EUID == 0 ]] || exit 1
if [[ $# == 0 ]]; then
    exec >/dev/ttyS0 2>&1
    printf '\nSLI_REGULAR_BACKUP_PROOF_STAGE mount_namespace\n'
    trap 'printf "\nSLI_REGULAR_BACKUP_PROOF_FAILED mount_namespace\n"' ERR
    /usr/bin/unshare --mount --propagation private -- /bin/bash "$0" isolated
    exit 0
fi
[[ $# == 1 && $1 == isolated ]] || exit 1
exec >/dev/ttyS0 2>&1
phase() {
    stage=$1
    printf '\nSLI_REGULAR_BACKUP_PROOF_STAGE %s\n' "$stage"
}
phase seed_manifest
trap 'printf "\nSLI_REGULAR_BACKUP_PROOF_FAILED %s\n" "$stage"; systemctl --no-block poweroff' ERR

seed=/run/sli-proof-seed
work=$(mktemp -d /run/sli-backup-guest.XXXXXXXX)
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C.UTF-8
export PSYCOPG_IMPL=binary

# Read-only seed, no pip or package manager inside the VM.
cd "$seed"
sha256sum --strict --check manifest.sha256
phase python_dependencies
python3 -I -B - "$seed" "$work" <<'PY'
from pathlib import Path
import runpy
import sys
import tarfile
import zipfile

sys.excepthook = lambda kind, _error, _traceback: print(
    "\nSLI_REGULAR_BACKUP_PROOF_EXCEPTION " + kind.__name__, file=sys.stderr, flush=True)
assert sys.version_info[:2] == (3, 13)
seed, work = map(Path, sys.argv[1:])
fixture = runpy.run_path(str(seed / "prove_regular_backup.py"))
with tarfile.open(seed / "source.tar") as archive:
    assert archive.pax_headers["comment"] == fixture["PIN"]
    archive.extractall(work / "source", filter="data")
checksum_names = [line.split("  ", 1)[1] for line in (seed / "manifest.sha256").read_text().splitlines()]
assert len(checksum_names) == 3
for name in checksum_names:
    if name.endswith(".whl"):
        with zipfile.ZipFile(seed / name) as wheel:
            wheel.extractall(work / "packages")
sys.path.insert(0, str(work / "packages"))
import psycopg
assert psycopg.__version__ == "3.3.4" and psycopg.pq.__impl__ == "binary"
PY

phase device_identity
udevadm settle --timeout=20
devices=(/dev/disk/by-id/virtio-sli-proof-db-part1 /dev/disk/by-id/virtio-sli-proof-db-part2
         /dev/disk/by-id/virtio-sli-proof-out)
mounts=(/mnt/sli-backup-proof/database /mnt/sli-backup-proof/same_disk /mnt/sli-backup-proof/archive)
database=$(readlink -e /dev/disk/by-id/virtio-sli-proof-db)
boot=$(readlink -e /dev/disk/by-id/virtio-sli-proof-boot)
archive=$(readlink -e "${devices[2]}")
[[ $archive != "$database" && $archive != "$boot" && $database != "$boot" ]]
for device in "${devices[@]}"; do
    [[ -L $device && -b $device ]]
    signatures=$(wipefs --no-act --noheadings --output TYPE "$device")
    [[ -z $signatures ]]
done
for part in "${devices[@]:0:2}"; do
    [[ $(lsblk --noheadings --nodeps --output PKNAME "$part") == "${database##*/}" ]]
done
phase filesystem_setup
for index in "${!devices[@]}"; do
    mkfs.ext4 -q -F "${devices[$index]}"
    mkdir -p "${mounts[$index]}"
    mount -o nosuid,nodev,noexec "${devices[$index]}" "${mounts[$index]}"
done

phase capture_proof
timeout 120 python3 -I -B - "$seed" "$work" <<'PY'
import json
from pathlib import Path
import runpy
import sys

sys.excepthook = lambda kind, _error, _traceback: print(
    "\nSLI_REGULAR_BACKUP_PROOF_EXCEPTION " + kind.__name__, file=sys.stderr, flush=True)
seed, work = map(Path, sys.argv[1:])
sys.path.insert(0, str(work / "packages"))
fixture = runpy.run_path(str(seed / "prove_regular_backup.py"))
volumes = fixture["guest_volumes"]()
print(json.dumps(fixture["run_capture_proof"](volumes, work / "source"), sort_keys=True), flush=True)
print("SLI_REGULAR_BACKUP_PROOF_PASS " + fixture["PIN"], flush=True)
PY
phase shutdown
systemctl --no-block poweroff
