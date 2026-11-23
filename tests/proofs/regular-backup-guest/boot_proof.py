"""Build a NoCloud seed and run the source-only proof in a disposable Debian VM."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

from prove_regular_backup import PIN

HERE = Path(__file__).resolve().parent
WHEELS = {
    "psycopg-3.3.4-py3-none-any.whl": "b6bbc25ccf05c8fad3b061d9db2ef0909a555171b84b07f29458a447253d679a",
    "psycopg_binary-3.3.4-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.whl":
        "c677c4ad433cb7150c8cd304a0769ae3bcfbe5ea0676eb53faa7b1443b16d0d3",
}
MARKER = b"SLI_REGULAR_BACKUP_PROOF_PASS " + PIN.encode("ascii")
RESULT = {
    "source": PIN, "scope": "source-only-synthetic-archive", "same_disk_peer": "rejected",
    "separate_guest_disk": "published_and_hash_verified", "schedule": "remained_off",
    "checkpoint_marker": "unchanged",
}
USER_DATA = """#cloud-config
datasource_list: [NoCloud]
users: []
disable_root: true
ssh_pwauth: false
network:
  config: disabled
runcmd:
  - - /bin/bash
    - -eu
    - -c
    - >-
      mkdir /run/sli-proof-seed;
      mount -t iso9660 -o ro,nosuid,nodev,noexec /dev/disk/by-label/CIDATA /run/sli-proof-seed;
      exec /bin/bash /run/sli-proof-seed/guest.sh
"""


def check_file(path, algorithm, expected):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"regular local file required: {path.name}")
    with path.open("rb") as stream:
        actual = hashlib.file_digest(stream, algorithm).hexdigest()
    if actual != expected:
        raise ValueError(f"{algorithm} mismatch: {path.name}")


def create_seed(source, wheelhouse, seed):
    seed.mkdir()
    archive = seed / "source.tar"
    subprocess.run(["git", "-C", str(source), "archive", "--format=tar",
                    f"--output={archive}", PIN, "deploy/linux"], check=True, timeout=30)
    with tarfile.open(archive) as tar:
        if tar.pax_headers.get("comment") != PIN:
            raise ValueError("Git archive lacks the exact source commit")
    for filename, digest in WHEELS.items():
        wheel = wheelhouse / filename
        check_file(wheel, "sha256", digest)
        shutil.copyfile(wheel, seed / filename)
        check_file(seed / filename, "sha256", digest)
    for name in ("prove_regular_backup.py", "guest.sh"):
        shutil.copyfile(HERE / name, seed / name)
    with archive.open("rb") as stream:
        checksums = {"source.tar": hashlib.file_digest(stream, "sha256").hexdigest()} | WHEELS
    (seed / "manifest.sha256").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in checksums.items()), encoding="ascii")
    (seed / "user-data").write_text(USER_DATA, encoding="ascii")
    (seed / "meta-data").write_text("instance-id: sli-backup-source-proof\nlocal-hostname: sli-proof\n", encoding="ascii")
    (seed / "network-config").write_text("version: 2\nethernets: {}\n", encoding="ascii")


def qemu_command():
    return [
        "qemu-system-x86_64", "-machine", "pc,accel=tcg", "-m", "2048", "-smp", "2",
        "-nodefaults", "-no-reboot", "-display", "none", "-monitor", "none", "-nic", "none",
        "-serial", "file:guest.log",
        "-drive", "file=boot.qcow2,if=none,format=qcow2,id=boot",
        "-device", "virtio-blk-pci,drive=boot,serial=sli-proof-boot,bootindex=1",
        "-drive", "file=db.raw,if=none,format=raw,id=proof-db",
        "-device", "virtio-blk-pci,drive=proof-db,serial=sli-proof-db",
        "-drive", "file=out.raw,if=none,format=raw,id=proof-out",
        "-device", "virtio-blk-pci,drive=proof-out,serial=sli-proof-out",
        "-drive", "file=seed.iso,media=cdrom,readonly=on,format=raw",
    ]


def require_terminal(serial):
    lines = serial.splitlines()
    expected = json.dumps(RESULT, sort_keys=True).encode("ascii")
    if (lines.count(MARKER) != 1 or lines.count(expected) != 1 or
            lines.index(MARKER) != lines.index(expected) + 1 or b"SLI_REGULAR_BACKUP_PROOF_FAILED" in lines):
        raise ValueError("guest did not emit the exact proof result before its marker")
    return RESULT


def run_guest(source, wheelhouse, image, digest, scratch):
    check_file(image, "sha512", digest)
    base = scratch / "base.qcow2"
    shutil.copyfile(image, base)
    check_file(base, "sha512", digest)
    base.chmod(0o444)
    info = json.loads(subprocess.check_output(
        ["qemu-img", "info", "--output=json", "-f", "qcow2", "base.qcow2"], cwd=scratch, timeout=30))
    if (info.get("format") != "qcow2" or "backing-filename" in info
            or "data-file" in info.get("format-specific", {}).get("data", {})):
        raise ValueError("a standalone authenticated qcow2 base is required")
    subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b",
                    "base.qcow2", "boot.qcow2"], cwd=scratch, check=True, timeout=30)
    for name in ("db.raw", "out.raw"):
        with (scratch / name).open("xb") as disk:
            disk.truncate(1024 * 1024 * 1024)
    # Partition a fresh regular file. Do not ask the host kernel to register it.
    subprocess.run(["sfdisk", "--no-reread", "--no-tell-kernel", "db.raw"], cwd=scratch,
                   input="label: gpt\nstart=2048,size=524288,type=L\nstart=526336,size=524288,type=L\n",
                   text=True, check=True, timeout=30)
    create_seed(source, wheelhouse, scratch / "seed")
    subprocess.run(["xorriso", "-as", "mkisofs", "-quiet", "-volid", "CIDATA", "-joliet", "-rock",
                    "-o", "seed.iso", "seed"], cwd=scratch, check=True, timeout=30)
    log = scratch / "guest.log"
    try:
        subprocess.run(qemu_command(), cwd=scratch, check=True, timeout=360)
        if log.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("guest log exceeded the proof limit")
        serial = log.read_bytes()
        result = require_terminal(serial)
    except (OSError, subprocess.SubprocessError, ValueError):
        if log.exists():
            with log.open("rb") as stream:
                stream.seek(max(0, log.stat().st_size - 12000))
                print(stream.read().decode("utf-8", errors="replace"), file=sys.stderr)
        raise
    check_file(base, "sha512", digest)
    print(json.dumps(result, sort_keys=True))
    print(MARKER.decode("ascii"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="Git checkout containing the exact proof commit")
    parser.add_argument("--wheelhouse", type=Path, required=True, help="directory with both pinned local wheels")
    parser.add_argument("--image", type=Path, required=True, help="authenticated Debian 13 generic amd64 qcow2")
    parser.add_argument("--image-sha512", required=True, help="independently authenticated image digest")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{128}", args.image_sha512):
        parser.error("--image-sha512 requires 128 lowercase hex digits")
    if sys.platform != "linux" or os.geteuid() == 0:
        parser.error("run the host launcher as an unprivileged user on Linux")
    with tempfile.TemporaryDirectory(prefix="sli-regular-backup-proof-", dir="/tmp") as directory:
        run_guest(args.source, args.wheelhouse, args.image, args.image_sha512, Path(directory))


if __name__ == "__main__":
    main()
