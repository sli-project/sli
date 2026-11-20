"""Host-owned updater versions; a single atomic pointer retains the rollback target."""

from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import uuid
from pathlib import Path

from scripts.maintenance.release_package import (
    UPDATER_FILES, UPDATER_RELEASE_VERSION, PackageError, _bounded_read, updater_files,
    _plain_source, extract_payload, read_json, verify_package,
)


# Exact separately provisioned operator launcher, not supplied by any package.
APPROVED_LAUNCHER_SHA256 = "cc6fde057650506169fa0480d7b9d590e3de43fee48cd28efe58793f85a97b20"


def check(condition, code="update_invalid_updater_state"):
    if not condition:
        raise PackageError(code)


def check_launcher(path, approved_sha256, *, owner_uid=0):
    """Inspect an explicitly located operator file; NEVER execute to probe it.

    approved_sha256 must come from reviewed release code, never the package,
    pointer, environment or a capability claim from the inspected file. This
    snapshot is not a durable authorization: admission calls again under lock
    and immediately before switching. Default ownership is the host operator
    (root); package metadata cannot change the pin or owner.
    """
    code = "update_launcher_upgrade_required"
    try:
        check(isinstance(approved_sha256, str) and re.fullmatch(r"[0-9a-f]{64}", approved_sha256), code)
        path = Path(path)
        check(path.is_absolute() and ".." not in path.parts, code)
        check(not any(part.is_symlink() for part in (path, *path.parents)), code)
        for parent in path.parents:
            metadata = parent.stat()
            sticky_root = metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX
            check(metadata.st_uid in {0, owner_uid}
                  and (not metadata.st_mode & 0o022 or sticky_root), code)
        # Nonblocking open also makes an unexpected FIFO fail without waiting.
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            check(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1
                  and opened.st_uid == owner_uid and not opened.st_mode & 0o022
                  and opened.st_size <= 1024 * 1024, code)
            raw = stream.read(1024 * 1024 + 1)
            check(len(raw) <= 1024 * 1024, code)
        digest = hashlib.sha256(raw).hexdigest()
        check(digest == approved_sha256, code)
        return digest
    except (OSError, TypeError, ValueError):
        raise PackageError(code) from None


def run_selftest(directory, version):
    """Run only after the CURRENT verifier has authenticated the whole snapshot."""
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(directory / "deploy/linux/sli_update.py"),
         "selftest", "--expected-version", version],
        cwd=directory, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, timeout=60, check=False,
    )
    check(result.returncode == 0, "update_updater_selftest_failed")


def sync_tree(root):
    """Persist directory entries before making their pointer durable."""
    if os.name != "nt":
        directories = [path for path in root.rglob("*") if path.is_dir()]
        for path in [*directories, root, root.parent, root.parent.parent]:
            descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)


class UpdaterComponent:
    def __init__(self, runtime, trust_store=None, *, selftest=run_selftest, source_root=None):
        self.state = Path(runtime) / "state"
        self.versions = Path(runtime) / "updater/versions"
        self.pointer = self.state / "updater.json"
        self.journal = self.state / "updater-journal.json"
        self.trust_store = Path(trust_store) if trust_store is not None else None
        self.selftest = selftest
        self.source_root = Path(source_root) if source_root else Path(__file__).resolve().parents[2]

    def save(self, path, value):
        from deploy.linux.sli_update import atomic_json
        atomic_json(path, value)

    def inventory(self, root, names=None):
        return {name: hashlib.sha256(_bounded_read(_plain_source(root / name, root), 128 * 1024 * 1024,
                                                  single_link=True)).hexdigest()
                for name in sorted(updater_files(UPDATER_RELEASE_VERSION) if names is None else names)}

    def validate(self, descriptor):
        check(isinstance(descriptor, dict) and set(descriptor) == {
            "component", "version", "os", "architecture", "directory", "files",
        })
        check(descriptor["component"] == "updater" and descriptor["os"] == "linux")
        check(descriptor["architecture"] in {"amd64", "arm64"})
        check(isinstance(descriptor["version"], str) and re.fullmatch(
            r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", descriptor["version"]))
        name = descriptor["directory"]
        check(isinstance(name, str) and re.fullmatch(re.escape(descriptor["version"]) + r"-[0-9a-f]{64}", name))
        root = self.versions / name
        check(not root.is_symlink() and root.resolve().is_relative_to(self.versions.resolve()))
        legacy = UPDATER_FILES - {
            "deploy/linux/backup.py", "deploy/linux/restore_existing.py", "deploy/linux/backup_restore_check.py",
        }
        secrets = {
            "deploy/linux/sli_secrets.py", "deploy/linux/secrets-manifest.json",
            "server/sli/agents/ca.py",
        }
        notifications = {"server/sli/core/notification_secrets.py", "server/sli/core/secret_files.py"}
        # Retained snapshots predate AD credential or notification provisioning,
        # or all secret helpers. Keep their exact inventories for rollback.
        ad_credentials = {"server/sli/core/ad_credential_secrets.py"}
        previous = UPDATER_FILES - ad_credentials
        previous_legacy = legacy - ad_credentials
        pre_notifications = previous - notifications
        pre_notifications_legacy = previous_legacy - notifications
        historical = (UPDATER_FILES, legacy, previous, previous_legacy,
                      pre_notifications, pre_notifications_legacy,
                      pre_notifications - secrets, pre_notifications_legacy - secrets)
        version = descriptor["version"]
        allowed = (*historical, updater_files(version)) if version == "1.1.0" else historical
        check(isinstance(descriptor["files"], dict) and set(descriptor["files"]) in allowed,
              "update_updater_files_changed")
        check(descriptor["files"] == self.inventory(root, descriptor["files"]), "update_updater_files_changed")
        return root

    def read_pointer(self):
        value = read_json(_bounded_read(self.pointer, 64 * 1024))
        check(set(value) == {"format_version", "current", "previous"} and value["format_version"] == 1)
        self.validate(value["current"])
        return value

    def baseline(self):
        machine = platform.machine().lower()
        check(sys.platform == "linux" and machine in {"x86_64", "aarch64", "amd64", "arm64"},
              "update_incompatible_platform")
        files = self.inventory(self.source_root)
        from scripts.maintenance.release_package import canonical_json
        digest = hashlib.sha256(canonical_json(files)).hexdigest()
        return {"component": "updater", "version": UPDATER_RELEASE_VERSION, "os": "linux",
                "architecture": "arm64" if machine in {"aarch64", "arm64"} else "amd64",
                "directory": UPDATER_RELEASE_VERSION + "-" + digest, "files": files}

    def bootstrap(self, descriptor):
        """Copy the trusted running release once; never modify any running file."""
        check(descriptor["version"] == UPDATER_RELEASE_VERSION
              and set(descriptor["files"]) == updater_files(UPDATER_RELEASE_VERSION),
              "update_updater_version_mismatch")
        root = self.versions / descriptor["directory"]
        root.mkdir(parents=True, exist_ok=True)
        check(not root.is_symlink() and root.resolve().is_relative_to(self.versions.resolve()))
        for name in sorted(descriptor["files"]):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            check(not path.is_symlink() and path.resolve().is_relative_to(root.resolve()))
            if not path.exists():
                with path.open("xb") as stream:
                    stream.write(_bounded_read(_plain_source(self.source_root / name, self.source_root), 128 * 1024 * 1024,
                                               single_link=True))
                    stream.flush()
                    os.fsync(stream.fileno())
        self.validate(descriptor)
        sync_tree(root)
        self.save(self.pointer, {"format_version": 1, "current": descriptor, "previous": None})

    def launcher_gate(self, manifest):
        if manifest["to_version"] == "1.1.0":
            check_launcher(self.state.parent / "tools/updater_launcher.py", APPROVED_LAUNCHER_SHA256)

    def preflight(self, package):
        """Authenticate and check prerequisites without creating even a lock."""
        check(self.trust_store is not None, "update_external_trust_required")
        check(not self.trust_store.resolve().is_relative_to(self.versions.parent.resolve())
              and not self.trust_store.resolve().is_relative_to((self.state / "updates").resolve()),
              "update_package_trust_forbidden")
        pointer = self.read_pointer() if self.pointer.exists() else None
        current = pointer["current"] if pointer else self.baseline()
        if pointer:
            check(self.source_root.resolve() == self.validate(current).resolve(), "update_current_updater_required")
        check(current["version"] == UPDATER_RELEASE_VERSION, "update_current_updater_required")
        disk = self.state
        while not disk.exists():
            disk = disk.parent
        try:
            verified = verify_package(package, self.trust_store, installed=current,
                                      free_bytes=shutil.disk_usage(disk).free, component="updater")
        except Exception:
            raise PackageError("update_package_verification_failed") from None
        self.launcher_gate(verified.manifest)
        return pointer, current, verified

    def apply(self, package, *, dry_run=False):
        from deploy.linux.sli_update import operation_lock
        before_pointer, before_current, before_verified = self.preflight(package)
        if dry_run:
            return "verified"
        with operation_lock(self.state):
            # Reauthenticate after acquiring the lock, including external trust.
            pointer, current, verified = self.preflight(package)
            check(pointer == before_pointer and current == before_current
                  and verified.archive_sha256 == before_verified.archive_sha256,
                  "update_current_updater_changed")
            server_journal = self.state / "update-journal.json"
            if server_journal.exists():
                check(read_json(_bounded_read(server_journal, 8 * 1024 * 1024))["status"]
                      in {"committed", "rolled_back", "rejected"}, "update_resume_required")
            if self.journal.exists():
                check(read_json(_bounded_read(self.journal, 64 * 1024))["status"]
                      in {"committed", "rolled_back", "rejected", "failed"}, "update_updater_recovery_required")
            record = {"format_version": 1, "operation": uuid.uuid4().hex, "status": "running", "phase": "verify"}
            if not pointer:
                self.bootstrap(current)
            expected_pointer = pointer or {"format_version": 1, "current": current, "previous": None}
            manifest = verified.manifest
            candidate = {"component": "updater", "version": manifest["to_version"], "os": "linux",
                         "architecture": manifest["compatibility"]["architecture"],
                         "directory": manifest["to_version"] + "-" + verified.archive_sha256,
                         "files": {item["path"]: item["sha256"] for item in manifest["files"]}}
            record.update(phase="stage", previous=current, candidate=candidate)
            self.save(self.journal, record)
            root = self.versions / candidate["directory"]
            try:
                extract_payload(verified, root)
                self.validate(candidate)
                sync_tree(root)
                record["phase"] = "selftest"
                self.save(self.journal, record)
                self.selftest(root, candidate["version"])
                self.validate(candidate)
                check(self.read_pointer() == expected_pointer, "update_current_updater_changed")
                self.launcher_gate(manifest)
                record["phase"] = "switch"
                self.save(self.journal, record)
                # One replace commits both the new current and its rollback target.
                self.save(self.pointer, {"format_version": 1, "current": candidate, "previous": current})
            except Exception as exc:
                # A replace may have succeeded before fsync reported failure.
                # Preserve the durable switch intent for explicit recovery.
                record["status"] = "recovery_required" if record["phase"] == "switch" else "failed"
                record["reason"] = "update_updater_activation_failed"
                self.save(self.journal, record)
                if isinstance(exc, PackageError) and str(exc) in {
                    "update_launcher_upgrade_required", "update_current_updater_changed",
                }:
                    raise
                raise PackageError("update_updater_activation_failed") from None
            record["status"], record["phase"] = "committed", "commit"
            self.save(self.journal, record)
            return "committed"

    def rollback(self):
        from deploy.linux.sli_update import operation_lock
        with operation_lock(self.state):
            # Recovery must work even if the current updater's files are damaged.
            pointer = read_json(_bounded_read(self.pointer, 64 * 1024))
            if self.journal.exists():
                record = read_json(_bounded_read(self.journal, 64 * 1024))
                if record.get("status") in {"running", "failed", "recovery_required"} and (
                    record.get("previous") == pointer.get("current") and record.get("candidate") is not None
                ):
                    # Stage/selftest was interrupted before the pointer changed.
                    root = self.validate(pointer["current"])
                    self.selftest(root, pointer["current"]["version"])
                    self.validate(pointer["current"])
                    record["status"], record["phase"] = "rolled_back", "commit"
                    record["candidate"] = pointer["current"]
                    self.save(self.journal, record)
                    return "rolled_back"
                if record.get("status") in {"rolling_back", "rolled_back"} and record.get("candidate") == pointer.get("current"):
                    self.validate(pointer["current"])
                    record["status"], record["phase"] = "rolled_back", "commit"
                    self.save(self.journal, record)
                    return "rolled_back"
            check(pointer.get("format_version") == 1 and pointer.get("previous") is not None,
                  "update_previous_updater_required")
            previous = pointer["previous"]
            root = self.validate(previous)
            self.selftest(root, previous["version"])
            self.validate(previous)
            record = {"format_version": 1, "operation": uuid.uuid4().hex,
                      "status": "rolling_back", "phase": "switch", "candidate": previous}
            self.save(self.journal, record)
            # Clearing previous makes a repeated rollback harmless, never a toggle.
            self.save(self.pointer, {"format_version": 1, "current": previous, "previous": None})
            record["status"], record["phase"] = "rolled_back", "commit"
            self.save(self.journal, record)
            return "rolled_back"


def selftest(expected_version=None):
    """Offline smoke check: local imports, helper syntax and a verifier KAT; no DB/API."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from deploy.linux import installation, sli_update, update_recovery, sli_secrets
    from scripts.maintenance import release_package
    from server.sli import release_package as package_verifier

    root = Path(__file__).resolve().parents[2]
    if expected_version is not None:
        check(expected_version == release_package.UPDATER_RELEASE_VERSION, "update_updater_version_mismatch")
    for module in (installation, sli_update, update_recovery, sli_secrets, release_package, package_verifier):
        check(Path(module.__file__).resolve().is_relative_to(root), "update_updater_import_mismatch")
    if UPDATER_RELEASE_VERSION == "1.1.0":
        from deploy.linux import installed_state, plugin_update, backup_activity
        from server.sli import plugin_validation
        for module in (installed_state, plugin_update, backup_activity, plugin_validation):
            check(Path(module.__file__).resolve().is_relative_to(root), "update_updater_import_mismatch")
        check(plugin_validation.ROOT == root, "update_updater_import_mismatch")
        release_package.read_json((root / "config/plugin_architecture_v3.json").read_bytes())
    for name in updater_files(UPDATER_RELEASE_VERSION):
        if name.endswith('.py'):
            compile((root / name).read_bytes(), name, "exec")
    sli_secrets.load_manifest()
    # RFC 8032, test 1: public verification material only.
    public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))
    signature = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    public.verify(signature, b"")
    try:
        public.verify(signature, b"changed")
    except InvalidSignature:
        pass
    else:
        raise PackageError("update_updater_verifier_failed")
    # Exercise the shipped verifier itself, including its rejection path.
    import base64
    key = Ed25519PrivateKey.generate()
    manifest = {"package_id": "sli.updater"}
    raw = release_package.canonical_json(manifest)
    trust = {"schema_version": 1, "keys": [{"key_id": "selftest", "revoked": False,
             "package_ids": ["sli.updater"],
             "public_key": base64.b64encode(key.public_key().public_bytes_raw()).decode("ascii")} ]}
    envelope = {"algorithm": "ed25519", "key_id": "selftest",
                "signature": base64.b64encode(key.sign(release_package.SIGNING_CONTEXT + raw)).decode("ascii")}
    release_package._verify_signature(manifest, raw, envelope, trust)
    try:
        release_package._verify_signature(manifest, raw + b"changed", envelope, trust)
    except release_package.PackageError:
        return "selftest_passed"
    raise PackageError("update_updater_verifier_failed")
