"""Trusted host helper sent to the PREVIOUS backup image, never package code.

Checkpoint receipts pin verified daily sets outside scheduled retention.
Recovery profiles select restored data; updates never capture new database dumps.
No candidate migrations or ledger writes run during rollback.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import stat
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

from deploy.linux import backup

RECOVERY_PROFILES = {
    "ui-only": (),
    "postgres": ("postgres",),
    "history": ("history", "warm"),
    "files": ("files",),
    "full": backup.COMPONENTS,
}


def invalid():
    raise ValueError("update_invalid_checkpoint")


def authenticate(manifest, checkpoint_key):
    if not re.fullmatch(r"[a-f0-9]{64}", checkpoint_key):
        invalid()
    document = {key: value for key, value in manifest.items() if key != "authentication"}
    raw = json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hmac.digest(bytes.fromhex(checkpoint_key), raw, "sha256").hex()


def open_directory(path):
    descriptor = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def seal_manifest(path, raw):
    """Publish authored bytes without following a shared manifest/temp pathname."""
    descriptor = open_directory(path.absolute())
    name = ".checkpoint-" + os.urandom(16).hex()
    try:
        opened = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=descriptor)
        try:
            with os.fdopen(opened, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, "manifest.json", src_dir_fd=descriptor, dst_dir_fd=descriptor)
            os.fsync(descriptor)
        finally:
            try:
                os.unlink(name, dir_fd=descriptor)
            except FileNotFoundError:
                pass
    finally:
        os.close(descriptor)


@contextmanager
def snapshot(root: Path, backup_id: str, *, temporary_root: Path | None = None, progress=None):
    """Open each component without following links; restore only the private copy.

    Directory descriptors pin ancestry even if a shared backup parent is renamed.
    Hashes describe the bytes copied, so concurrent writes fail verification before DROP.
    """
    path = root.absolute() / backup_id
    if not path.is_relative_to(root.absolute()) or path.resolve() != path:
        invalid()
    descriptor = open_directory(path)
    try:
        with tempfile.TemporaryDirectory(prefix="sli-checkpoint-", dir=(temporary_root or
                                         os.environ.get("SLI_UPDATE_SNAPSHOT_ROOT"))) as temporary:
            destination = Path(temporary)
            inventory = {}

            def copy_tree(source, target, prefix=""):
                for name in os.listdir(source):
                    logical = prefix + name
                    info = os.stat(name, dir_fd=source, follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=source)
                        try:
                            (target / name).mkdir(mode=0o700)
                            if progress is not None:
                                progress()
                            copy_tree(child, target / name, logical + "/")
                        finally:
                            os.close(child)
                    elif stat.S_ISREG(info.st_mode):
                        opened = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=source)
                        with os.fdopen(opened, "rb") as stream, (target / name).open("xb") as output:
                            info = os.fstat(stream.fileno())
                            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                                invalid()
                            digest, size = hashlib.sha256(), 0
                            while chunk := stream.read(1024 * 1024):
                                digest.update(chunk)
                                size += len(chunk)
                                output.write(chunk)
                                if progress is not None:
                                    progress()
                            if logical != "manifest.json":
                                inventory[logical] = {"sha256": digest.hexdigest(), "size": size}
                            if not size and progress is not None:
                                progress()
                    else:
                        invalid()

            try:
                copy_tree(descriptor, destination)
                yield destination, inventory
            finally:
                if progress is not None:
                    from deploy.linux.operation_wait import remove_tree

                    remove_tree(destination)
    finally:
        os.close(descriptor)


def checkpoint(root: Path, operation: str, checkpoint_key: str, recovery_profile: str | None = None,
               daily_backup: dict | None = None):
    from deploy.linux.operation_wait import made_progress

    if not re.fullmatch(r"[a-f0-9]{32}", operation):
        raise ValueError("update_invalid_operation")
    if recovery_profile is None and "SLI_BACKUP_FILES_ROOT" in os.environ:
        recovery_profile = "full"
    if recovery_profile is not None and recovery_profile not in RECOVERY_PROFILES:
        invalid()
    with backup.backup_lock(root):
        target = root / "update-checkpoints" / operation
        target.mkdir(parents=True, exist_ok=True)
        if target.absolute() != target.resolve():
            invalid()
        complete = backup.successful_backups(target)
        if complete:
            path = complete[-1]
            backup_id = str(path.relative_to(root))
            with snapshot(root, backup_id, progress=made_progress) as (copy, inventory):
                manifest = json.loads((copy / "manifest.json").read_bytes())
                if (manifest.get("operation") != operation or manifest.get("content_checksums") != inventory
                        or manifest.get("recovery_profile") != recovery_profile
                        or not hmac.compare_digest(manifest.get("authentication", ""), authenticate(manifest, checkpoint_key))):
                    invalid()
                raw = (copy / "manifest.json").read_bytes()
        else:
            from deploy.linux.backup_restore_check import verified_daily_backup

            selected = verified_daily_backup(root)
            if daily_backup is not None and selected != daily_backup:
                raise RuntimeError("update_fresh_daily_backup_required")
            path = target / selected["backup_id"]
            if path.exists():
                with snapshot(root, str(path.relative_to(root)), progress=made_progress) as (copy, inventory):
                    manifest = json.loads((copy / "manifest.json").read_bytes())
                    if (inventory or manifest.get("operation") != operation
                            or manifest.get("daily_backup") != selected
                            or manifest.get("recovery_profile") != recovery_profile
                            or not hmac.compare_digest(manifest.get("authentication", ""),
                                                       authenticate(manifest, checkpoint_key))):
                        invalid()
                    raw = (copy / "manifest.json").read_bytes()
            else:
                path.mkdir(mode=0o700)
                manifest = {"operation": operation, "daily_backup": selected,
                            "recovery_profile": recovery_profile, "content_checksums": {}}
                manifest["authentication"] = authenticate(manifest, checkpoint_key)
                raw = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
                seal_manifest(path, raw)
            backup_id = str(path.relative_to(root))
        return {"backup_id": backup_id, "checkpoint_sha256": hashlib.sha256(raw).hexdigest(),
                **({"daily_backup": manifest["daily_backup"]} if "daily_backup" in manifest else {})}


def restore(root: Path, backup_id: str, operation: str, checkpoint_sha256: str, checkpoint_key: str):
    from deploy.linux.operation_wait import made_progress

    if (not re.fullmatch(r"[a-f0-9]{32}", operation)
            or not re.fullmatch(r"[a-f0-9]{64}", checkpoint_sha256)
            or not re.fullmatch(r"update-checkpoints/" + operation + r"/\d{8}T\d{6}\.\d{6}Z", backup_id)):
        invalid()
    with backup.backup_lock(root), snapshot(root, backup_id, progress=made_progress) as (path, inventory):
        raw = (path / "manifest.json").read_bytes()
        if hashlib.sha256(raw).hexdigest() != checkpoint_sha256:
            invalid()
        manifest = json.loads(raw)
        if "daily_backup" in manifest:
            if (inventory or manifest.get("operation") != operation
                    or not hmac.compare_digest(manifest.get("authentication", ""), authenticate(manifest, checkpoint_key))):
                invalid()
            selected = manifest["daily_backup"]
            identifier = selected["backup_id"]
            if not isinstance(identifier, str) or not backup.BACKUP_NAME.fullmatch(identifier):
                invalid()
            # Copy/hash only during an actual rollback, before any destructive SQL.
            with snapshot(root, identifier, progress=made_progress) as (daily, daily_inventory):
                daily_raw = (daily / "manifest.json").read_bytes()
                source = json.loads(daily_raw)
                if (hashlib.sha256(daily_raw).hexdigest() != selected["manifest_sha256"]
                        or source.get("content_checksums") != daily_inventory):
                    invalid()
                from deploy.linux.restore_existing import restore_components

                profile = manifest["recovery_profile"]
                components = RECOVERY_PROFILES.get(profile) if profile is not None else ("postgres",)
                if components is None:
                    invalid()
                if components:
                    restore_components(daily, root, source, components, replace_existing=True,
                                       files_root=Path(os.environ["SLI_BACKUP_FILES_ROOT"]) if "files" in components else None)
            return
        if (manifest.get("operation") != operation or manifest.get("status") != "success"
                or manifest.get("backup_id") != Path(backup_id).name
                or manifest.get("content_checksums") != inventory
                or not hmac.compare_digest(manifest.get("authentication", ""), authenticate(manifest, checkpoint_key))):
            invalid()
        if "recovery_profile" in manifest:
            from deploy.linux.restore_existing import restore_components

            selected = RECOVERY_PROFILES.get(manifest["recovery_profile"])
            if selected is None or list(selected) != manifest.get("recovery_components"):
                invalid()
            if selected:
                restore_components(path, root, manifest, selected, replace_existing=True,
                                   files_root=Path(os.environ["SLI_BACKUP_FILES_ROOT"]) if "files" in selected else None)
            return
        if "postgres/toc.dat" not in inventory:
            invalid()
        # Validate readback expectations before any privileged database operation.
        counts = manifest["components"]["postgres"]["row_counts"]
        ledger = manifest["migration_ledger_max_version"]
        with backup.pg_passfile() as passfile:
            with backup.pg_connect(passfile, "postgres", autocommit=True) as connection:
                # Writers are stopped by the host before this helper is invoked.
                # Repeating a partially interrupted restore starts from template0.
                connection.execute("DROP DATABASE IF EXISTS sli WITH (FORCE)")
                connection.execute("CREATE DATABASE sli OWNER sli_migration TEMPLATE template0")
            backup.pg_tool(["pg_restore", "--no-password", "--exit-on-error", "--format=directory",
                            "--host=postgres", "--username=postgres", "--dbname=sli", "--jobs=2",
                            str(path / "postgres")], passfile)
            with backup.pg_connect(passfile) as connection:
                if (backup.row_counts(connection) != counts
                        or connection.execute("SELECT max(version) FROM public.schema_migrations").fetchone()[0]
                        != ledger):
                    raise RuntimeError("update_restore_readback_failed")


def check_backup(root: Path, operation: str, checkpoint_key: str):
    """Select nightly evidence before fencing writers; never capture or drill here."""
    if not re.fullmatch(r"[a-f0-9]{32}", operation):
        raise ValueError("update_invalid_operation")
    from deploy.linux.backup_restore_check import verified_daily_backup

    with backup.backup_lock(root):
        return {"status": "verified", "verification": "nightly", "daily_backup": verified_daily_backup(root)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["backup", "restore", "check"])
    parser.add_argument("identifier")
    args = parser.parse_args()
    try:
        root = Path("/backups")
        identity = json.loads(args.identifier)
        if args.action == "backup":
            print(json.dumps(checkpoint(root, **identity)))
        elif args.action == "check":
            print(json.dumps(check_backup(root, **identity)))
        else:
            restore(root, **identity)
            print("update_checkpoint_restored")
    except RuntimeError as exc:
        if str(exc) == "update_fresh_daily_backup_required" and args.action != "restore":
            print(json.dumps({"status": "waiting", "reason_code": "update_fresh_daily_backup_required"}))
            return 0
        print("update_checkpoint_failed", file=sys.stderr)
        return 1
    except Exception:  # Docker logs must also contain only fixed diagnostics.
        print("update_checkpoint_failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
