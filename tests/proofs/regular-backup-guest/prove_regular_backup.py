"""Source-only regular backup proof on disposable QEMU guest block devices."""

import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from contextlib import ExitStack, nullcontext
from unittest.mock import patch

PIN = "1b5daf4e66640b7390105b4b5345332deca6f9ce"
GUEST_ROOT = Path("/mnt/sli-backup-proof")
DEVICES = {
    "database": "virtio-sli-proof-db-part1",
    "same_disk": "virtio-sli-proof-db-part2",
    "archive": "virtio-sli-proof-out",
}
SYNTHETIC_EVENT = b"sli-disposable-backup-fixture\n"
CHECKPOINT_MARKER = b"independent-fixture-checkpoint\n"


def require(condition, code):
    if not condition:
        raise RuntimeError(code)


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=10).stdout.strip()


def source_pin(source):
    require(source == source.resolve(strict=True), "source_path_not_canonical")
    require(command("git", "-C", str(source), "rev-parse", "HEAD") == PIN, "source_pin_mismatch")
    require(not command("git", "-C", str(source), "status", "--porcelain", "--untracked-files=normal"),
            "source_checkout_not_clean")


def guest_volumes():
    require(sys.platform == "linux" and os.geteuid() == 0, "qemu_linux_root_required")
    require(command("/usr/bin/systemd-detect-virt", "--vm") in {"qemu", "kvm"}, "qemu_guest_required")
    require(GUEST_ROOT == GUEST_ROOT.resolve(strict=True), "proof_mount_parent_not_canonical")
    volumes = {}
    for purpose, serial in DEVICES.items():
        mount = GUEST_ROOT / purpose
        expected = Path("/dev/disk/by-id") / serial
        require(expected.is_symlink(), "synthetic_device_id_missing")
        guessed = expected.resolve(strict=True)
        require(stat.S_ISBLK(guessed.stat().st_mode), "synthetic_device_not_block")
        row, = json.loads(command("/usr/bin/findmnt", "--json", "--mountpoint", str(mount),
                                  "--output", "SOURCE,TARGET,FSTYPE,UUID,PROPAGATION,OPTIONS"))["filesystems"]
        require(mount == mount.resolve(strict=True) and row["target"] == str(mount)
                and row["fstype"] == "ext4" and row["propagation"] == "private"
                and "rw" in row["options"].split(",") and isinstance(row["uuid"], str) and row["uuid"]
                and Path(row["source"]).samefile(guessed) and mount.stat().st_dev == guessed.stat().st_rdev,
                "unexpected_guest_mount")
        require({child.name for child in mount.iterdir()} <= {"lost+found"}, "fixture_volume_not_fresh")
        volumes[purpose] = (mount, row["uuid"])
    require(len({mount.stat().st_dev for mount, _ in volumes.values()}) == 3
            and len({uuid for _, uuid in volumes.values()}) == 3, "three_distinct_filesystems_required")
    return {purpose: mount for purpose, (mount, _) in volumes.items()}


def rejected(call, code):
    try:
        call()
    except RuntimeError as error:
        require(str(error) == code, "unexpected_rejection_code")
        return
    raise RuntimeError("unsafe_candidate_accepted")


def make_directory(base, name):
    path = base / name
    path.mkdir(mode=0o700)
    return path


def synthetic_dump(target):
    target.mkdir(mode=0o700)
    toc = b"source-only-fixture-not-a-pg-dump\n"
    roles = b"-- source-only fixture; no roles or credentials\n"
    (target / "toc.dat").write_bytes(toc)
    (target.parent / "roles.sql").write_bytes(roles)
    return {"format": "directory", "roles_file": "roles.sql", "role_passwords": False,
            "size_bytes": len(toc) + len(roles), "database_size_bytes": 0, "row_counts": {}}


def run_capture_proof(volumes, source):
    sys.path.insert(0, str(source))
    from deploy.linux import backup, native_backup, native_backup_settings as settings
    from deploy.linux import native_host, native_install, native_runtime, operation_wait
    from deploy.linux import native_clickhouse_endpoint as site

    db_mount = volumes["database"]
    archive_mount = volumes["archive"]
    peer_mount = volumes["same_disk"]
    require(native_backup.same_disk(db_mount, peer_mount) is True, "same_backing_disk_not_observed")
    require(native_backup.same_disk(db_mount, archive_mount) is False, "separate_backing_disk_not_observed")
    for mount in volumes.values():
        native_host.Host().backup_trusted(mount)

    control = make_directory(db_mount, "proof-control")
    pgdata = make_directory(control, "pgdata")
    data = make_directory(control, "data")
    state_dir = make_directory(control, "state")
    transactions = make_directory(control, "transactions")
    history = make_directory(data, "backup-status") / "summary.json"
    recovery = make_directory(control, "canonical-recovery")
    checkpoint = make_directory(recovery, "upgrade-checkpoints") / "fixture-marker"
    checkpoint.write_bytes(CHECKPOINT_MARKER)
    (data / "synthetic-event.txt").write_bytes(SYNTHETIC_EVENT)
    bad = make_directory(peer_mount, "destination")
    good = make_directory(archive_mount, "destination")

    def no_timer_change(enabled):
        require(enabled is False, "fixture_forbids_enabling_timer")

    def capture_admission(root, *, regular=False):
        require(root.stat().st_dev == archive_mount.stat().st_dev, "unexpected_output_device")
        native_backup.require_separate_disk(root, [pgdata])

    def synthetic_companion(path):
        path.mkdir(mode=0o700)
        (path / "fixture-marker").write_text("source-only synthetic companion\n")

    fixture_machine = "a" * 64
    backup.write_json(state_dir / "installed.json", {"release": str(source), "manifest_sha256": PIN})
    overrides = {
        native_backup: {"ROOT": recovery, "DATA": data, "STATE": state_dir, "DRILLS": control / "drills",
                        "settings": lambda: {"SLI_DEPLOYMENT_MODE": "native", "SLI_BACKUP_RETENTION": "1",
                                             "SLI_BACKUP_WEEKLY_RETENTION": "0"},
                        "companion": synthetic_companion},
        settings: {"POLICY": state_dir / "backup-settings.json", "apply_schedule": no_timer_change},
        native_host: {"MOUNT": str(db_mount), "POSTGRES_DATA_DIRECTORY": str(pgdata),
                      "administrative_lock": nullcontext},
        native_host.Host: {"receipt": lambda self: {}, "require_backup_mount": lambda self: None,
                           "backup_machine_id": lambda self: fixture_machine},
        native_install: {"backup_schedule": lambda: "disabled"},
        native_runtime: {"release": lambda: (source, {}, PIN), "STATE": state_dir, "TRANSACTIONS": transactions},
        backup: {"capture_admission": capture_admission, "dump_postgres": synthetic_dump,
                 "clickhouse_targets": lambda: ()},
        operation_wait: {"history_path": lambda backup_root=None: history, "machine_id": lambda: fixture_machine},
        site: {"site_configuration": dict},
        tempfile: {"tempdir": str(control)},
    }
    with ExitStack() as stack:
        for target, values in overrides.items():
            stack.enter_context(patch.multiple(target, **values))
        with backup.backup_lock(recovery):
            initial = settings.load_or_migrate()
            require(not initial["enabled"] and initial["revision"] == "0", "fresh_policy_not_off")
            rejected(lambda: settings.update(initial, {"enabled": False, "path": str(bad), "revision": "0"}),
                     "native_backup_root_same_device")
            require(settings.read_policy() == initial and not any(bad.iterdir()), "refusal_left_output")
            # Also check a previously saved destination at the actual capture entry point.
            settings.save_policy(initial | {"path": str(bad), "identity": settings.mount_identity(bad)})
        rejected(native_backup.capture, "native_backup_root_same_device")
        require(not any(bad.iterdir()), "capture_refusal_left_output")
        with backup.backup_lock(recovery):
            settings.save_policy(initial)
            configured = settings.update(initial, {"enabled": False, "path": str(good), "revision": "0"})
        require(configured["storage_status"] == "ready" and not configured["enabled"], "valid_selection_not_ready")
        require(native_backup.capture(scheduled=True) is None and not any(good.iterdir()), "off_schedule_wrote")
        final = native_backup.capture()
        expected = good / settings.ARCHIVES
        require(final.parent == expected and final.stat().st_dev == archive_mount.stat().st_dev, "wrong_output_device")
        manifest, payload, _ = native_backup.verify(final)
        receipt = json.loads((expected / "last-result.json").read_bytes())
        summary = json.loads(history.read_bytes())
        require(receipt["terminal"] is True and receipt["status"] == "backup_created"
                and receipt["backup_id"] == manifest["backup_id"]
                and summary["same_disk_as_postgres"] is False
                and (payload / "files" / "synthetic-event.txt").read_bytes() == SYNTHETIC_EVENT,
                "synthetic_archive_verification_failed")
        require((payload / "postgres" / "toc.dat").read_bytes() == b"source-only-fixture-not-a-pg-dump\n",
                "synthetic_dump_marker_missing")
        require([path for path in expected.iterdir() if path.is_dir()] == [final], "unexpected_archive_or_partial")
        require(not any(bad.iterdir()) and checkpoint.read_bytes() == CHECKPOINT_MARKER
                and list(checkpoint.parent.iterdir()) == [checkpoint], "negative_or_checkpoint_boundary_changed")
    return {"source": PIN, "scope": "source-only-synthetic-archive", "same_disk_peer": "rejected",
            "separate_guest_disk": "published_and_hash_verified", "schedule": "remained_off",
            "checkpoint_marker": "unchanged"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="clean checkout of the exact merged source")
    args = parser.parse_args()
    volumes = guest_volumes()
    source_pin(args.source)
    print(json.dumps(run_capture_proof(volumes, args.source), sort_keys=True))


if __name__ == "__main__":
    main()
