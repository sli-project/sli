"""Independent host updater for signed packages and the Docker Compose project sli."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import importlib.machinery
import json
import os
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit
from urllib.request import urlopen

def require_snapshot_imports(root):
    """Reject namespace collisions before any application package is imported."""
    for name in ("deploy", "scripts", "server"):
        spec = importlib.machinery.PathFinder.find_spec(name)
        locations = ([spec.origin] if spec and spec.origin
                     else list(spec.submodule_search_locations or ()) if spec else [])
        if not locations or any(not Path(path).resolve().is_relative_to(root) for path in locations):
            raise RuntimeError("update_updater_import_mismatch")


if __package__ in {None, ""}:
    snapshot_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(snapshot_root))
    require_snapshot_imports(snapshot_root)

from server.sli.release_package import (
    ImageLimits, PackageError as UpdateError, canonical_json as canonical, extract_payload,
    _bounded_read, _version, read_json, safe_package_path as safe_path, verify_package,
    require_complete_updater, UPDATER_RELEASE_VERSION, MIGRATION_MARKER,
)

# Kept identical to backup.py: neither process imports the other runtime.
PG_CAPACITY_SQL = """SELECT json_build_object(
 'cluster_id', (SELECT system_identifier::text FROM pg_control_system()),
 'postmaster_start', pg_postmaster_start_time()::text,
 'data_directory', current_setting('data_directory'),
 'database_size_bytes', pg_database_size(current_database()),
 'tablespaces', (SELECT json_agg(json_build_object('oid', oid::bigint,
 'location', pg_tablespace_location(oid)) ORDER BY oid) FROM pg_tablespace))"""

def pg_capacity_paths(point: dict) -> dict:
    data = point["data_directory"]
    if not isinstance(data, str) or not data.startswith("/") or "\x00" in data:
        raise ValueError("linux_backup_invalid_capacity")
    paths = {"data": data, "wal": data.rstrip("/") + "/pg_wal",
             "default": data.rstrip("/") + "/base", "global": data.rstrip("/") + "/global"}
    spaces = point["tablespaces"]
    if not isinstance(spaces, list) or not 2 <= len(spaces) <= 128:
        raise ValueError("linux_backup_invalid_capacity")
    seen = set()
    for space in spaces:
        oid, location = space["oid"], space["location"]
        if type(oid) is not int or oid <= 0 or oid in seen or not isinstance(location, str):
            raise ValueError("linux_backup_invalid_capacity")
        seen.add(oid)
        if oid in {1663, 1664}:
            if location:
                raise ValueError("linux_backup_invalid_capacity")
        elif location.startswith("/") and "\x00" not in location:
            paths[f"tablespace:{oid}"] = location
        else:
            raise ValueError("linux_backup_invalid_capacity")
    if not {1663, 1664} <= seen:
        raise ValueError("linux_backup_invalid_capacity")
    return paths

LIMIT = 1024 * 1024
DELTA_KEYS = {"SLI_BACKUP_INTERVAL_SECONDS", "SLI_BACKUP_START_DELAY_SECONDS", "SLI_BACKUP_RETENTION", "SLI_BACKUP_TIME"}
# Core migrations may register bundled packages without a separate plugin update.
# Admit only the reviewed immutable SQL (including its historical CRLF encoding).
CORE_PLUGIN_REGISTRATIONS = {
    "config/postgres_migrations/221_sigma_chain_plugins.sql": (
        "sli.sigma", "1.0.0", {
            "8a510a8dd2d1710bad898b872a558785f6c92d98289f72c4babee44a9594a8c9",
            "fd5462f8e6e2787fb54cd6b1bd0f8c906758a27817c1e09a2908440ba9e646b1",
        },
    ),
}
PREFLIGHT_SQL = """BEGIN READ ONLY;
SELECT json_build_object(
    'migration_ledger_max', (SELECT coalesce(max(version), 0) FROM public.schema_migrations),
    'migration_ledger', (SELECT coalesce(json_agg(json_build_object(
        'version', version, 'name', name, 'sha256', to_jsonb(m)->>'sha256') ORDER BY version), '[]'::json)
        FROM public.schema_migrations m),
    'installed_release_available', to_regclass('public.installed_release_v1') is not null,
    'plugins', (SELECT coalesce(json_agg(json_build_object(
        'plugin_id', plugin_id, 'version', package_version, 'installed', package_lifecycle='registered',
        'enabled', desired_activation='enabled_manual') ORDER BY plugin_id), '[]'::json)
        FROM public.plugin_installations_v1));
COMMIT;"""


def require(condition, code="update_invalid_manifest"):
    if not condition:
        raise UpdateError(code)


def bundled_core_plugins(manifest, *, applied_ledger=()):
    result = {}
    if manifest.get("component") != "server":
        return result
    for path, (plugin_id, version, checksums) in CORE_PLUGIN_REGISTRATIONS.items():
        checksum = manifest["migrations"].get(path)
        if checksum is not None:
            require(checksum in checksums, "update_plugin_registration_mismatch")
            version_number = int(Path(path).name.split("_", 1)[0])
            if version_number not in {row["version"] for row in applied_ledger}:
                result[plugin_id] = {"version": version, "migrations": {}}
    return result


def reason_code(exc, fallback):
    value = str(exc)
    return value if isinstance(exc, UpdateError) and re.fullmatch(r"update_[a-z0-9_]+", value) else fallback


def runtime_version_matches(version, installed):
    return version == installed["version"] or (
        version is None and bool(installed.get("adoption"))
        and re.fullmatch(r"adopted-[1-9][0-9]*", installed["version"]) is not None)


def sha256(path):
    import hashlib
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def protected_path(path, *, directory=False):
    """Host state is private; writable ancestors cannot replace trusted records."""
    path = Path(path).absolute()
    for parent in reversed(path.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode), "update_unsafe_state")
        if os.name != "nt":
            # A root-owned sticky temporary root cannot replace our owned child.
            sticky_root = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            require(info.st_uid in {0, os.geteuid()} and (not info.st_mode & 0o022 or sticky_root),
                    "update_unsafe_state")
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
            "update_unsafe_state")
    if os.name != "nt":
        require(info.st_uid == os.geteuid() and not info.st_mode & 0o022, "update_unsafe_state")


def checked_override(journal, key):
    protected_path(journal[key])
    require(sha256(journal[key]) == journal[key + "_sha256"], "update_override_changed")
    return journal[key]


def acceptance_compose_order(journal, files):
    """Recover an order only when its rendered fingerprint will be verified.

    Historical journals stored a mapping, whose canonical JSON sorts its keys.
    Prefer the operator's original-file subsequence; completely replaced layouts
    can use the stored order only if it reproduces the authenticated fingerprint.
    Pin the proved order in the acceptance intent for interrupted publication.
    """
    recorded = (journal.get("candidate_acceptance") or {}).get("source_compose_order")
    if recorded is not None:
        require(isinstance(recorded, list) and len(recorded) == len(set(recorded))
                and set(recorded) == set(journal["compose_files"]), "update_compose_changed")
        return recorded
    supplied = [str(path) for path in files if str(path) in journal["compose_files"]]
    return supplied if len(supplied) == len(set(supplied)) == len(journal["compose_files"]) else list(journal["compose_files"])


def parse_json(raw):
    return read_json(raw.encode("utf-8") if isinstance(raw, str) else raw, object_only=False)


def complete_overlay(current, release):
    """Retain the installation contract while applying a bounded release overlay."""
    def reference(item, field):
        identity = item.get("target" if field == "volumes" else "source") if isinstance(item, dict) else item
        require(isinstance(identity, str) and (field != "volumes" or isinstance(item, dict)), "update_overlay_conflict")
        return identity

    def merge(left, right):
        result = json.loads(json.dumps(left))
        for key, value in right.items():
            if isinstance(value, dict) and isinstance(result.get(key), dict):
                result[key] = merge(result[key], value)
            elif key in {"volumes", "secrets"} and isinstance(value, list) and isinstance(result.get(key), list):
                # Compose service mounts/secrets have unique target/source identities.
                retained = {reference(item, key): item for item in result[key]}
                require(len(retained) == len(result[key]), "update_overlay_conflict")
                for item in value:
                    identity = reference(item, key)
                    old = retained.get(identity)
                    managed = (key == "volumes" and identity == "/run/notification-setup") or (
                        key == "secrets" and identity == "notification_db_password")
                    require(old is None or old == item or managed, "update_overlay_conflict")
                    # Replace the bounded managed reference completely; stale source,
                    # type-specific options and secret targets must not survive.
                    retained[identity] = item
                result[key] = list(retained.values())
            else:
                result[key] = value
        return result

    result = merge(current, release)
    if "volumes" in current:
        # Storage definitions are opaque installation state, not release deltas.
        require(all(key not in release.get("volumes", {}) or release["volumes"][key] == value
                    for key, value in current["volumes"].items()), "update_volume_ownership")
        result["volumes"] = json.loads(json.dumps(current["volumes"]))
    return result


def archive_members(archive, *, allow_directories=False, max_entries=10000):
    members = {}
    folded = set()
    for count, item in enumerate(archive, 1):
        require(count <= max_entries, "update_image_entry_limit")
        if allow_directories and item.isdir():
            safe_path(item.name.rstrip("/"))
            continue
        safe_path(item.name)
        require(item.isfile() and item.name.casefold() not in folded, "update_invalid_archive")
        members[item.name] = item
        folded.add(item.name.casefold())
        require(len(members) <= 10000, "update_invalid_archive")
    return members


def read_small(archive, item):
    require(item.size <= LIMIT, "update_metadata_too_large")
    return archive.extractfile(item).read()


def image_inventory(image_path, manifest, sanitized, *, limits=None, applied_ledger=()):
    """Check docker-save config and final migration files without starting a container.

    Write a tagless docker-save archive: docker load must never replace live tags.
    Only classic single-image docker-save archives are accepted in schema v2.
    """
    import io
    import gzip

    limits = limits or ImageLimits()
    entries = 0
    ledger = {}
    ledger_variants = {}
    applied = {row["version"]: row for row in applied_ledger}

    class BoundedTarInfo(tarfile.TarInfo):
        @classmethod
        def fromtarfile(cls, archive):
            # tarfile calls this again for hidden GNU/PAX headers as well.
            nonlocal entries
            entry = super().fromtarfile(archive)
            if entry is not None:
                entries += 1
                require(entries <= limits.max_entries, "update_image_entry_limit")
            return entry

    def layer_source(archive, item):
        stream = archive.extractfile(item)
        magic = stream.read(2)
        stream.seek(0)
        return gzip.GzipFile(fileobj=stream) if magic == b"\x1f\x8b" else stream

    def inspect_layer(expanded, inventory):
        seen = set()
        with tarfile.open(fileobj=expanded, mode="r|", tarinfo=BoundedTarInfo) as layer:
            for entry in layer:
                path = entry.name.removeprefix("./")
                if entry.isdir():
                    path = path.removesuffix("/")
                    if entry.name in {".", "./"}:
                        continue  # Explicit TAR root directory has no overlay effect.
                # Permit one leading ./, but no other extractor-dependent aliases.
                require(path and not PurePosixPath(path).is_absolute()
                        and not any(part in {"", ".", ".."} for part in path.split("/"))
                        and path not in seen, "update_unsafe_path")
                seen.add(path)
                require(not (path in {"opt", "opt/sli", "opt/sli/config", "opt/sli/config/postgres_migrations"}
                             and not entry.isdir()), "update_image_migration_invalid")
                require(not (path.startswith("opt/sli/config/postgres_migrations/")
                             and (entry.issym() or entry.islnk())), "update_image_migration_invalid")
                if path.startswith("opt/sli/config/postgres_migrations/") and ".wh." in path:
                    raise UpdateError("update_migration_whiteout_forbidden")
                if path in {".wh.opt", ".wh..wh..opq", "opt/.wh.sli", "opt/sli/.wh.config", "opt/sli/config/.wh.postgres_migrations",
                            "opt/.wh..wh..opq", "opt/sli/.wh..wh..opq", "opt/sli/config/.wh..wh..opq"}:
                    raise UpdateError("update_migration_whiteout_forbidden")
                if path.startswith("opt/sli/config/postgres_migrations/") and path.endswith(".sql"):
                    require(entry.isfile(), "update_image_migration_invalid")
                    logical = path.removeprefix("opt/sli/")
                    safe_path(logical)
                    require(entry.size <= LIMIT, "update_image_migration_invalid")
                    body = layer.extractfile(entry).read()
                    checksum = hashlib.sha256(body).hexdigest()
                    inventory[logical] = checksum
                    match = re.fullmatch(r"(\d+)_.*\.sql", Path(logical).name)
                    if match and not re.search(r"(?:\.rollback|_rollback)\.sql$", logical):
                        markers = MIGRATION_MARKER.findall(body.decode("utf-8"))
                        require(markers and int(match[1]) > 0 and int(markers[-1][0]) == int(match[1]),
                                "update_image_migration_invalid")
                        ledger[logical] = {"version": int(match[1]), "name": markers[-1][1], "sha256": checksum}
                        from deploy.linux.installed_state import migration_checksum_variants
                        ledger_variants[logical] = migration_checksum_variants(body)

    with tarfile.open(image_path, "r:", tarinfo=BoundedTarInfo) as archive:
        members = archive_members(archive, allow_directories=True, max_entries=limits.max_entries)
        records = parse_json(read_small(archive, members["manifest.json"]))
        require(isinstance(records, list) and len(records) == 1, "update_image_inventory_invalid")
        record = records[0]
        config = read_small(archive, members[safe_path(record["Config"])])
        require("sha256:" + hashlib.sha256(config).hexdigest() == manifest["image"]["digest"], "update_image_digest_mismatch")
        config = parse_json(config)
        require(config["config"].get("Labels", {}).get("org.opencontainers.image.version") == manifest["to_version"],
                "update_image_version_mismatch")
        require(all(config[key] == manifest["compatibility"][key] for key in ("os", "architecture")), "update_incompatible_platform")
        layers = record["Layers"]
        diffs = config["rootfs"]["diff_ids"]
        require(len(layers) == len(diffs) and len(layers) <= limits.max_layers, "update_image_inventory_invalid")
        inventory = {}
        total_bytes = 0
        for name, diff in zip(layers, diffs, strict=True):
            item = members[safe_path(name)]
            # One bounded expansion feeds both the diff hash and TAR parser. Include
            # padding and PAX metadata in the byte budget, before tarfile allocates it.
            with tempfile.TemporaryFile(dir=Path(sanitized).parent) as expanded:
                budget = min(limits.max_layer_bytes, limits.max_total_bytes - total_bytes,
                             item.size * limits.max_ratio)
                digest, size = hashlib.sha256(), 0
                with layer_source(archive, item) as source:
                    while chunk := source.read(min(1024 * 1024, budget - size + 1)):
                        size += len(chunk)
                        require(size <= budget, "update_image_expansion_limit")
                        digest.update(chunk)
                        expanded.write(chunk)
                total_bytes += size
                require("sha256:" + digest.hexdigest() == diff, "update_image_layer_mismatch")
                expanded.seek(0)
                inspect_layer(expanded, inventory)
        require(inventory == manifest["migrations"], "update_image_migrations_mismatch")
        # Exclude repositories/OCI indexes and every other reference-bearing file.
        record = {"Config": record["Config"], "RepoTags": [], "Layers": layers}
        with tarfile.open(sanitized, "w") as target:
            raw = canonical([record])
            metadata = tarfile.TarInfo("manifest.json")
            metadata.size = len(raw)
            target.addfile(metadata, io.BytesIO(raw))
            for name in dict.fromkeys([record["Config"], *layers]):
                target.addfile(members[name], archive.extractfile(members[name]))
    require(len(ledger) == len({row["version"] for row in ledger.values()}), "update_migration_ledger_mismatch")
    for logical, row in ledger.items():
        previous = applied.get(row["version"])
        if previous is not None:
            require(previous["name"] == row["name"] and previous["sha256"] in ledger_variants[logical],
                    "update_migration_ledger_mismatch")
            # Preserve the database attestation, using only the final layer's
            # file bytes to prove equivalence with the image inventory.
            ledger[logical] = dict(previous)
    return sorted(ledger.values(), key=lambda row: row["version"])


def load_deltas(directory, manifest):
    """V1 deltas only change bounded, nonsecret backup settings."""
    merged = {}
    for key in ("compose_delta", "config_delta"):
        if manifest[key] is None:
            continue
        delta = parse_json(_bounded_read(directory / manifest[key], LIMIT))
        require(isinstance(delta, dict) and set(delta) == {"backup"}, "update_unsupported_delta")
        values = delta["backup"]
        require(isinstance(values, dict) and set(values) <= DELTA_KEYS, "update_unsupported_delta")
        for name, value in values.items():
            if name == "SLI_BACKUP_TIME":
                require(isinstance(value, str) and re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", value)
                        and name not in merged, "update_unsupported_delta")
                merged[name] = value
                continue
            require(isinstance(value, str) and value.isascii() and value.isdigit()
                    and 0 <= int(value) <= 2147483647, "update_unsupported_delta")
            minimum = 60 if name == "SLI_BACKUP_INTERVAL_SECONDS" else 1 if name == "SLI_BACKUP_RETENTION" else 0
            require(int(value) >= minimum and name not in merged, "update_unsupported_delta")
            merged[name] = value
    return merged

PHASES = ("verify", "stage", "checkpoint", "drain", "migrate", "activate", "health", "commit")
INFRA = {"postgres", "clickhouse", "warm-tier"}
AUXILIARY_INFRA = {"clickhouse-restore"}


def notification_services(image, secret_directory, public_url):
    """Canonical bounded addition, also used to upgrade retained Compose installs."""
    private = {"type": "bind", "source": str(Path(secret_directory) / "notifications"),
               "target": "/var/lib/notification-secrets"}
    common = {"image": image, "restart": "unless-stopped", "read_only": True,
              "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"],
              "tmpfs": ["/tmp:mode=1777"], "mem_limit": "256m", "pids_limit": 64}
    socket_mount = {"type": "bind", "source": str(Path(secret_directory) / "notification-control"), "target": "/run/notification-setup"}
    return {
        "notification-setup": {**common, "user": "0:0", "cap_add": ["CHOWN"],
            "command": ["notification-setup"], "environment": {"SLI_PUBLIC_URL": public_url},
            "volumes": [private, socket_mount],
            "healthcheck": {"test": ["CMD", "python", "-m", "deploy.linux.notification_health", "setup"],
                            "interval": "15s", "timeout": "5s", "retries": 4}},
        "notification-delivery": {**common, "command": ["notification-delivery"],
            "environment": {"ADLOG_DB_BACKEND": "postgres",
                "ADLOG_PG_DSN": "host=postgres port=5432 dbname=sli user=sli_notification_login",
                "ADLOG_PG_PASSWORD_FILE": "/run/secrets/notification_db_password",
                "SLI_NOTIFICATION_TELEGRAM_TOKEN_FILE": "/var/lib/notification-secrets/notification_telegram_token",
                "SLI_NOTIFICATION_TELEGRAM_CONFIG_FILE": "/var/lib/notification-secrets/telegram.json",
                "SLI_NOTIFICATION_SMTP_PASSWORD_FILE": "/var/lib/notification-secrets/notification_smtp_password",
                "SLI_NOTIFICATION_SMTP_CONFIG_FILE": "/var/lib/notification-secrets/smtp.json"},
            "secrets": ["notification_db_password"], "volumes": [{**private, "read_only": True}],
            "healthcheck": {"test": ["CMD", "python", "-m", "deploy.linux.notification_health", "delivery"],
                            "interval": "15s", "timeout": "5s", "retries": 4, "start_period": "30s"}},
    }


def add_notification_services(candidate, *, image, secret_directory, public_url):
    candidate["services"].update(notification_services(image, secret_directory, public_url))
    candidate.setdefault("secrets", {})["notification_db_password"] = {
        "file": str(Path(secret_directory) / "notification_db_password")}
    migrate = candidate["services"].setdefault("migrate", {"image": image})
    # Compose merges unique secret sources and mount targets with retained config.
    if "notification_db_password" not in migrate.setdefault("secrets", []):
        migrate["secrets"].append("notification_db_password")
    migrate.setdefault("environment", {})["SLI_NOTIFICATION_DB_PASSWORD_FILE"] = "/run/secrets/notification_db_password"
    mounts = candidate["services"]["api"].setdefault("volumes", [])
    mounts[:] = [mount for mount in mounts if mount.get("target") != "/run/notification-setup"]
    mounts.append({
        "type": "bind", "source": str(Path(secret_directory) / "notification-control"), "target": "/run/notification-setup", "read_only": True})


def drain_failure_diagnostic(journal):
    """Latest attempt only; bounded tail, safe names and explicit uncertainty."""
    attempts = journal.get("drain_services", [])
    if not isinstance(attempts, list):
        return {}
    # A newer successful attempt supersedes an old failure. Never resurrect
    # older failures after their stop RPCs have successfully settled.
    attempt = next((item for item in reversed(attempts[-128:]) if isinstance(item, dict)), None)
    if not attempt or attempt.get("failure_resolved") is True:
        return {}
    reason = attempt.get("failure_reason")
    reasons = {"still_running", "exit_code", "container_identity_unverified", "readback_unavailable"}
    if not isinstance(reason, str) or reason not in reasons:
        return {}
    values = attempt.get("failed_services", [])
    names = sorted({name for name in values[:128]
                    if isinstance(name, str) and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", name)}) if isinstance(values, list) else []
    known = reason in {"still_running", "exit_code"}
    result = {"drain_failure_reason": reason, "drain_failure_certainty": "observed" if known else "unknown"}
    if names:
        result["drain_failed_services" if known else "drain_unverified_services"] = names
    return result


def drain_failure_message(result):
    if result.get("drain_failure_certainty") == "unknown":
        names = result.get("drain_unverified_services", [])
        return "Остановка не подтверждена (unknown)" + (": " + ", ".join(names) if names else "") + "."
    if result.get("drain_failed_services"):
        return "Сервисы последней ошибки остановки: " + ", ".join(result["drain_failed_services"]) + "."
    return ""


def active_services(journal, previous=False):
    return sorted(set(journal["services"]) | (set() if previous else set(journal.get("added_services", []))))
INTERRUPT_SERVICES = {"api", "backup", "remote-access", "semantic", "storage-lifecycle",
                      "post-collection", "what-where-when", "entity-state",
                      "ad-snapshot-manifest-coordinator"}
# This installed revision predates cooperative shutdown. Its eight workers
# can exit 130 on SIGINT; its API can hang at process exit. A missing SIGTERM
# handler permits only the attested, transaction-free bridge below. Newer and
# unknown images must stop softly with exit 0.
LEGACY_INTERRUPT_REVISIONS = {"3b252ad93d913044b68a387862e2e60223d5b56b"}


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".update-")
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def operation_lock(state, *, protect_state=True):
    """OS lock is released on process death; the disk journal survives.

    Only fresh installation, without trusted update records, skips state checks.
    """
    state.mkdir(parents=True, mode=0o700, exist_ok=True)
    if protect_state:
        protected_path(state, directory=True)
    state.chmod(0o700)
    lock = state / "update.lock"
    if lock.exists() or lock.is_symlink():
        protected_path(lock)
    descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "a+b") as stream:
        if os.name == "nt":
            import msvcrt
            stream.seek(0)
            stream.write(b"0")
            stream.flush()
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


class InstallationOverride(str):
    """Checked operation snapshot replacing one authenticated installation layer."""
    def __new__(cls, source, target):
        value = super().__new__(cls, source)
        value.target = target
        return value


def helper_preload_source(policy_source, sandbox_source):
    """Program prefix that provides modules the previous image does not contain yet.

    The host-owned backup helpers run inside the previous trusted image. A newer
    backup.py imports modules added after that image was built (T086), so they are
    registered from host-owned sources before the helpers are executed.
    """
    return ("import sys, types\n"
            "import deploy.linux as _linux_package\n"
            "def _preload(name, source):\n"
            "    module = types.ModuleType('deploy.linux.' + name)\n"
            "    module.__package__ = 'deploy.linux'\n"
            "    exec(source, module.__dict__)\n"
            "    sys.modules['deploy.linux.' + name] = module\n"
            "    setattr(_linux_package, name, module)\n"
            f"_preload('backup_policy', {policy_source!r})\n"
            f"_preload('restore_sandbox', {sandbox_source!r})\n")


class DockerHost:
    def __init__(self, compose_files, health_url, ca_file, timeout=300, tls_min_validity=86400,
                 drain_timeout=300):
        self.files = [Path(file).resolve() for file in compose_files]
        self.health_url, self.ca_file, self.timeout = health_url, ca_file, timeout
        self.tls_min_validity = tls_min_validity
        self.drain_timeout = drain_timeout
        self.persist_drain = lambda journal: None
        require(drain_timeout > 0, "update_invalid_drain_timeout")
        require(tls_min_validity > 0, "update_invalid_tls_window")
        require(health_url.startswith("https://") and health_url.endswith("/api/health/ready"), "update_invalid_health_url")

    def command(self, args, *, stdin=None, timeout=21600):
        result = subprocess.run(args, input=stdin, capture_output=True, timeout=timeout, check=False)
        require(result.returncode == 0, "update_docker_failed")
        return result.stdout.decode("utf-8")

    def compose_files(self, override=None, *, replacement=None):
        if isinstance(override, InstallationOverride):
            require(replacement is None, "update_compose_override_binding")
            replacement = {override.target: str(override)}
            override = None
        replacement = replacement or {}
        require(all(sum(str(path) == target for path in self.files) == 1 for target in replacement),
                "update_compose_override_binding")
        command = ["docker", "compose", "-p", "sli"]
        for path in self.files:
            command.extend(["-f", str(replacement.get(str(path), path))])
        if override:
            command.extend(["-f", str(override)])
        return command

    def compose(self, args, override=None, *, stdin=None, timeout=None):
        return self.command([*self.compose_files(override), *args], **({'stdin': stdin} if stdin is not None else {}),
                            **({'timeout': timeout} if timeout is not None else {}))

    def validate_snapshot_binding(self, journal):
        binding = journal.get("compose_snapshot")
        if "compose_snapshot" not in journal:
            return None  # Authenticated legacy overrides retain append semantics.
        require(isinstance(binding, dict) and set(binding) == {"mode", "path"}
                and binding["mode"] == "replace-installation-v1", "update_compose_override_mode")
        directory = Path(journal["directory"])
        require(re.fullmatch(r"[a-f0-9]{32}", journal["operation"])
                and directory.name == journal["operation"] and directory.parent.name == "updates",
                "update_compose_override_binding")
        target = str(directory.parent.parent / "install-compose.json")
        protected_path(target)
        require(binding["path"] == target and sum(str(path) == target for path in self.files) == 1
                and target in journal["compose_files"] and sha256(target) == journal["compose_files"][target],
                "update_compose_override_binding")
        require({str(path): sha256(path) for path in self.files} == journal["compose_files"], "update_compose_changed")
        return target

    def operation_override(self, journal, key):
        target = self.validate_snapshot_binding(journal)
        source = checked_override(journal, key)
        return InstallationOverride(source, target) if target is not None else source

    def validate_operation_overrides(self, journal):
        fingerprints = {}
        for key in ("previous_override", "candidate_override"):
            override = self.operation_override(journal, key)
            config = (self.configuration({override.target: str(override)})
                      if isinstance(override, InstallationOverride) else
                      parse_json(self.compose(["config", "--format", "json"], override)))
            self.ownership_preflight(journal["previous"], config)
            fingerprints[key] = hashlib.sha256(canonical(config)).hexdigest()
        if journal.get("compose_snapshot") is not None and "snapshot_fingerprints" in journal:
            require(fingerprints == journal["snapshot_fingerprints"], "update_configuration_changed")
        return fingerprints

    def plugin_preflight(self, runtime, installed, manifest):
        from deploy.linux.installed_state import validate
        self.inspect_installation(installed)
        config = parse_json(self.compose(["config", "--format", "json"]))
        source = str((Path(runtime) / "plugins").resolve())
        locks = set()
        for name, service in config["services"].items():
            if name != "api" and service.get("environment", {}).get("SLI_PLUGIN_RUNTIME_DIR") is None:
                continue
            require(service.get("environment", {}).get("SLI_PLUGIN_RUNTIME_DIR") == "/opt/sli/plugins"
                    and any(volume.get("type") == "bind" and volume.get("target") == "/opt/sli/plugins"
                            and volume.get("read_only") is True and volume.get("source") == source
                            for volume in service.get("volumes", [])), "update_plugin_mount_required")
            require(service.get("environment", {}).get("SLI_PLUGIN_LOCK_DIR") == "/opt/sli/plugin-locks",
                    "update_plugin_mount_required")
            lock_mounts = [volume for volume in service.get("volumes", []) if volume.get("target") == "/opt/sli/plugin-locks"
                           and volume.get("type") == "bind" and volume.get("read_only") is True]
            require(len(lock_mounts) == 1, "update_plugin_mount_required")
            locks.add(lock_mounts[0]["source"])
        require(len(locks) == 1, "update_plugin_mount_required")
        observed = self.observe()
        self.ownership_preflight(installed, config)
        require(observed.get("installed_release_available") is not False, "update_installed_registry_required")
        validate(installed, observed, runtime)
        return observed

    def plugin_drain(self, runtime, manifest):
        # The fence is durable on the host. All containers share Linux flock on
        # the read-only bind; this also works with a Windows-hosted updater.
        self.compose(["exec", "-T", "api", "python", "-m", "server.sli.plugins.update_runtime",
                      "drain", manifest["plugin_id"], "--timeout", str(self.timeout)])

    def plugin_health(self, runtime, manifest):
        self.compose(["exec", "-T", "api", "python", "-m", "server.sli.plugins.update_runtime",
                      "health", manifest["plugin_id"], "--version", manifest["plugin_version"]])

    def containers(self):
        rows = self.compose(["ps", "--all", "--format", "json"]).strip()
        if not rows:
            return []
        return json.loads(rows) if rows.startswith("[") else [json.loads(row) for row in rows.splitlines()]

    def image_id(self, tag):
        return self.command(["docker", "image", "inspect", "--format", "{{.Id}}", tag]).strip()

    def publish_pg_capacity(self):
        """Existing host Docker authority; no authority is delegated to backup."""
        started = datetime.now(timezone.utc).isoformat()
        deadline = time.monotonic() + 20
        identity = self.compose(["ps", "--quiet", "postgres"], timeout=5).strip()
        require(bool(identity) and "\n" not in identity, "update_capacity_unavailable")
        point = parse_json(self.compose([
            "exec", "-T", "postgres", "psql", "--no-psqlrc", "--no-password", "--username=postgres",
            "--dbname=sli", "--quiet", "--no-align", "--tuples-only", "--set=ON_ERROR_STOP=1",
            "--command", PG_CAPACITY_SQL], timeout=5))
        paths = {}
        for role, path in pg_capacity_paths(point).items():
            require(time.monotonic() < deadline, "update_capacity_unavailable")
            resolved = self.compose(["exec", "-T", "postgres", "readlink", "-e", "--", path], timeout=5).strip()
            require(resolved.startswith("/") and not any(char in resolved for char in "\n\r\x00"),
                    "update_capacity_unavailable")
            paths[role] = resolved
        mounts = self.compose(["exec", "-T", "postgres", "cat", "/proc/self/mountinfo"], timeout=5)
        require(0 < len(mounts) <= 1024 * 1024, "update_capacity_unavailable")
        for line in mounts.splitlines():
            fields = line.split()
            require(len(fields) >= 10 and "-" in fields, "update_capacity_unavailable")
            mounted = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), fields[4])
            require(mounted.startswith("/") and "\x00" not in mounted, "update_capacity_unavailable")
            # Nested mounts could put relation/version directories on a different
            # disk than their tablespace root. Unsupported layouts fail closed;
            # never substitute the parent filesystem's free space.
            nested = any(mounted.startswith(path.rstrip("/") + "/") for path in paths.values())
            require(not nested or mounted in paths.values(), "update_capacity_unmapped_mount")
        filesystems = {}
        for role, path in paths.items():
            require(time.monotonic() < deadline, "update_capacity_unavailable")
            fields = self.compose(["exec", "-T", "postgres", "stat", "-f", "--format=%S %a %i",
                                   "--", path], timeout=5).strip().split()
            require(len(fields) == 3, "update_capacity_unavailable")
            block, available = int(fields[0]), int(fields[1])
            require(block > 0 and available >= 0, "update_capacity_unavailable")
            filesystems[role] = {"device": fields[2], "free_bytes": block * available}
        require(time.monotonic() < deadline, "update_capacity_unavailable")
        require(self.compose(["ps", "--quiet", "postgres"], timeout=5).strip() == identity,
                "update_capacity_unavailable")
        # Requery after probing: restart or tablespace remapping invalidates sample.
        after = parse_json(self.compose([
            "exec", "-T", "postgres", "psql", "--no-psqlrc", "--no-password", "--username=postgres",
            "--dbname=sli", "--quiet", "--no-align", "--tuples-only", "--set=ON_ERROR_STOP=1",
            "--command", PG_CAPACITY_SQL], timeout=5))
        require(all(point[key] == after[key] for key in
                    ("cluster_id", "postmaster_start", "data_directory", "tablespaces")),
                "update_capacity_unavailable")
        document = {"point": point, "filesystems": filesystems, "observed_at_utc": started}
        self.compose(["exec", "-T", "backup", "python", "-m", "deploy.linux.backup", "--publish-pg-capacity"],
                     stdin=json.dumps(document).encode(), timeout=5)
        return {"status": "published"}

    def observe(self):
        # Use the existing data container so status also works while writers are drained.
        # Local socket authentication must be provisioned by the trusted installer.
        observed = parse_json(self.compose(["exec", "-T", "postgres", "psql", "--no-password", "--username=postgres",
            "--dbname=sli", "--quiet", "--no-align", "--tuples-only", "--set=ON_ERROR_STOP=1", "--command", PREFLIGHT_SQL]))
        observed["installed_release"] = None
        if observed.get("installed_release_available"):
            observed["installed_release"] = parse_json(self.compose([
                "exec", "-T", "postgres", "psql", "--no-password", "--username=postgres", "--dbname=sli",
                "--quiet", "--no-align", "--tuples-only", "--set=ON_ERROR_STOP=1", "--command",
                "BEGIN READ ONLY; SELECT coalesce((SELECT json_build_object('installation_key', installation_key, "
                "'operation', operation, 'inventory', inventory) FROM public.installed_release_v1), 'null'::json); COMMIT;"]))
        observed["engine_free_bytes"] = int(self.compose(["exec", "-T", "postgres", "df", "--output=avail", "-B1", "/"]).splitlines()[-1])
        observed["services"] = {}
        for row in self.containers():
            if row["Service"] not in (INFRA | AUXILIARY_INFRA) and row["State"] == "running":
                # Do not publish docker inspect output: it includes environment/secrets.
                facts = parse_json(self.command(["docker", "inspect", row["ID"]]))[0]
                image = parse_json(self.command(["docker", "image", "inspect", facts["Image"]]))[0]
                observed["services"][row["Service"]] = {
                    "version": (image["Config"].get("Labels") or {}).get("org.opencontainers.image.version"),
                    "image_digest": facts["Image"], "image_tag": facts["Config"]["Image"],
                }
        return observed

    def publish_installed(self, previous, candidate, operation):
        from deploy.linux.installed_state import installation_key, inventory
        config = parse_json(self.compose(["config", "--format", "json"]))
        self.ownership_preflight(candidate, config)
        require(installation_key(previous) == installation_key(candidate), "update_foreign_installation")
        require(re.fullmatch(r"[a-f0-9]{32}", operation), "update_invalid_operation")
        payload = canonical({"installation_key": installation_key(candidate), "operation": operation,
                             "previous": inventory(previous), "candidate": inventory(candidate)}).hex()
        statement = """BEGIN;
DO $installed$
DECLARE p jsonb := convert_from(decode('%s','hex'),'UTF8')::jsonb;
    current public.installed_release_v1%%rowtype; item record; actual jsonb;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('sli_installed_release_v179'));
    SELECT * INTO current FROM public.installed_release_v1 WHERE singleton FOR UPDATE;
    IF FOUND AND (current.installation_key<>p->>'installation_key' OR
        NOT (current.inventory=p->'previous' OR
             (current.inventory=p->'candidate' AND current.operation=p->>'operation'))) THEN
        RAISE EXCEPTION 'update_installed_registry_mismatch';
    END IF;
    SELECT jsonb_agg(jsonb_build_object('version',version,'name',name,'sha256',sha256) ORDER BY version)
        INTO actual FROM public.schema_migrations;
    IF actual IS DISTINCT FROM p->'candidate'->'migration_ledger' THEN
        RAISE EXCEPTION 'update_migration_ledger_mismatch';
    END IF;
    FOR item IN SELECT plugin_id,package_version FROM public.plugin_installations_v1
        WHERE package_lifecycle='registered' FOR UPDATE LOOP
        IF p->'candidate'->'plugins'->item.plugin_id IS NULL OR
           item.package_version NOT IN (p->'previous'->'plugins'->item.plugin_id->>'version',
                                        p->'candidate'->'plugins'->item.plugin_id->>'version') THEN
            RAISE EXCEPTION 'update_plugin_registry_mismatch';
        END IF;
    END LOOP;
    IF (SELECT count(*) FROM public.plugin_installations_v1 WHERE package_lifecycle='registered') <>
       (SELECT count(*) FROM jsonb_object_keys(p->'candidate'->'plugins')) THEN
        RAISE EXCEPTION 'update_plugin_registry_mismatch';
    END IF;
    UPDATE public.plugin_installations_v1 i SET package_version=v.value->>'version', revision=i.revision+1
        FROM jsonb_each(p->'candidate'->'plugins') v
        WHERE i.plugin_id=v.key AND i.package_lifecycle='registered'
            AND i.package_version IS DISTINCT FROM v.value->>'version';
    INSERT INTO public.installed_release_v1(singleton,installation_key,operation,inventory)
        VALUES(true,p->>'installation_key',p->>'operation',p->'candidate')
        ON CONFLICT(singleton) DO UPDATE SET operation=excluded.operation,inventory=excluded.inventory,
            updated_at_utc=now();
END $installed$;
COMMIT;""" % payload
        # Full inventories can exceed Linux's per-argument limit. Keep the
        # guarded transaction intact and stream it without exposing it in argv.
        self.compose(["exec", "-T", "postgres", "psql", "--no-password", "--username=postgres", "--dbname=sli",
                      "--quiet", "--set=ON_ERROR_STOP=1", "--file", "-"], stdin=statement.encode('utf-8'))

    def tls_preflight(self):
        from cryptography import x509

        address = urlsplit(self.health_url)
        try:
            context = ssl.create_default_context(cafile=str(self.ca_file))
            with socket.create_connection((address.hostname, address.port or 443), timeout=5) as connection:
                with context.wrap_socket(connection, server_hostname=address.hostname) as tls:
                    certificate = x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))
        except (OSError, ValueError):
            raise UpdateError("update_tls_verification_failed") from None
        now = datetime.now(timezone.utc)
        require(certificate.not_valid_before_utc <= now
                and certificate.not_valid_after_utc > now + timedelta(seconds=max(self.timeout, self.tls_min_validity)),
                "update_tls_validity_window")

    def ownership_preflight(self, installed, config):
        require(config.get("name") == "sli" and installed.get("compose_project") == "sli",
                "update_foreign_installation")
        volumes = config.get("volumes", {})
        require(installed.get("volumes") == {key: value["name"] for key, value in volumes.items()},
                "update_volume_ownership")
        for row in self.containers():
            labels = parse_json(self.command(["docker", "inspect", "--format", "{{json .Config.Labels}}", row["ID"]]))
            require(labels and labels.get("com.docker.compose.project") == "sli", "update_foreign_installation")
        for definition in volumes.values():
            name = definition["name"]
            volume = parse_json(self.command(["docker", "volume", "inspect", name]))[0]
            project = (volume.get("Labels") or {}).get("com.docker.compose.project")
            require(project == "sli" or (definition.get("external") and project is None), "update_volume_ownership")
            consumers = self.command(["docker", "ps", "-aq", "--filter", f"volume={name}"]).split()
            for container in consumers:
                labels = parse_json(self.command(["docker", "inspect", "--format", "{{json .Config.Labels}}", container]))
                require(labels and labels.get("com.docker.compose.project") == "sli", "update_volume_ownership")

    def secrets_preflight(self, config, required):
        from deploy.linux.sli_secrets import validate_compose
        validate_compose(config)
        for name in required:
            for secret in config["services"][name].get("secrets", []):
                definition = config.get("secrets", {}).get(secret["source"], {})
                path = Path(definition.get("file", ""))
                require(path.is_file() and path.stat().st_size > 0 and os.access(path, os.R_OK), "update_required_secret_missing")

    def ensure_secrets(self, installed):
        from deploy.linux.sli_secrets import SecretError, ensure, validate_compose

        self.inspect_installation(installed)
        config = parse_json(self.compose(["config", "--format", "json"]))
        self.ownership_preflight(installed, config)
        try:
            validate_compose(config)
        except SecretError as exc:
            if isinstance(exc, UpdateError):
                raise
            raise UpdateError(str(exc)) from None
        definitions = config.get("secrets", {})
        if not definitions:
            return
        paths = {name: Path(spec.get("file", "")) for name, spec in definitions.items()}
        require(all(path.is_absolute() and path.name == name for name, path in paths.items()),
                "update_secret_directory_layout_required")
        directories = {path.parent for path in paths.values()}
        require(len(directories) == 1, "update_secret_directory_layout_required")
        try:
            # Host-owned provisioning precedes every container-changing phase.
            # Missing/invalid certificate bundles fail without rotating them.
            ensure(directories.pop(), names=definitions)
        except Exception:
            raise UpdateError("update_secrets_ensure_failed") from None

    def preflight(self, installed, manifest):
        bundled_core_plugins(manifest)
        self.inspect_installation(installed)
        config = parse_json(self.compose(["config", "--format", "json"]))
        self.ownership_preflight(installed, config)
        required = {"api", "backup", "migrate", *INFRA}
        required.update(row["Service"] for row in self.containers() if row["State"] == "running")
        self.secrets_preflight(config, required)
        self.tls_preflight()
        free = parse_json(self.compose(["exec", "-T", "backup", "python", "-c",
            "import json, shutil; print(json.dumps({'free': shutil.disk_usage('/backups').free}))"]))["free"]
        require(free >= manifest["required_free_disk"], "update_insufficient_backup_disk")
        observed = self.observe()
        require(observed["engine_free_bytes"] >= manifest["required_free_disk"], "update_insufficient_engine_disk")
        return observed

    def runtime_matches(self, journal, previous=False):
        from deploy.linux.installed_state import ledger_matches
        target = journal["previous"] if previous else {
            "version": journal["manifest"]["to_version"], "image_digest": journal["manifest"]["image"]["digest"]}
        observed = self.observe()
        services = active_services(journal, previous)
        require(set(services) <= set(observed["services"]), "update_runtime_mismatch")
        require(all(runtime_version_matches(observed["services"][name]["version"], target)
                    and observed["services"][name]["image_digest"] == target["image_digest"]
                    and observed["services"][name]["image_tag"] == (journal["previous"]["image_tag"] if previous else journal["candidate_tag"])
                    for name in services), "update_runtime_mismatch")
        ledger = journal["manifest"]["compatibility"]["migration_ledger_max"] if previous else max(
            (int(Path(path).name.split("_", 1)[0]) for path in journal["manifest"]["migrations"]
             if Path(path).name.split("_", 1)[0].isdigit()), default=0)
        require(observed["migration_ledger_max"] == ledger, "update_migration_ledger_mismatch")
        target_inventory = journal["previous"] if previous else {
            "migrations": journal["manifest"]["migrations"], "migration_ledger": journal["candidate_ledger"]}
        ledger_matches(target_inventory, observed)
        return observed

    def acceptance_preflight(self, journal):
        """Read-only equivalence check; operator file names are not authority.

        Render the authenticated operation using its ORIGINAL files, then compare
        the supplied complete effective configuration. Never adopt an arbitrary
        override merely because its image and top-level volumes look familiar.
        """
        for path, checksum in journal["compose_files"].items():
            protected_path(path)
            require(sha256(path) == checksum, "update_compose_changed")
        for path in self.files:
            protected_path(path)
        original = DockerHost(acceptance_compose_order(journal, self.files), self.health_url, self.ca_file,
                              self.timeout, self.tls_min_validity, self.drain_timeout)
        require(original.deployment_fingerprint() == journal["deployment_fingerprint"],
                "update_configuration_changed")
        original.validate_operation_overrides(journal)
        override = original.operation_override(journal, "candidate_override")
        expected = (original.configuration({override.target: str(override)})
                    if isinstance(override, InstallationOverride) else
                    parse_json(original.compose(["config", "--format", "json"], override)))
        config = self.configuration()
        require(config == expected, "update_configuration_changed")
        candidate = {**journal["previous"], "version": journal["manifest"]["to_version"],
                     "image_tag": journal["candidate_tag"], "image_digest": journal["manifest"]["image"]["digest"]}
        self.ownership_preflight(candidate, config)
        self.inspect_installation(candidate)
        required = {*active_services(journal), *INFRA}
        rows = self.containers()
        # Compose's own service hashes bind the supplied model to the running
        # containers, not just to a plausible unused file supplied by an operator.
        hashes = {}
        for line in self.compose(["config", "--hash", "*"]).splitlines():
            fields = line.split()
            require(len(fields) == 2 and fields[0] not in hashes
                    and re.fullmatch(r"[a-f0-9]{64}", fields[1]), "update_configuration_changed")
            hashes[fields[0]] = fields[1]
        for name in required:
            selected = [row for row in rows if row["Service"] == name]
            require(len(selected) == 1 and selected[0]["State"] == "running", "update_runtime_mismatch")
            live_hash = self.command(["docker", "inspect", "--format",
                '{{index .Config.Labels "com.docker.compose.config-hash"}}', selected[0]["ID"]]).strip()
            require(name in hashes and live_hash == hashes[name], "update_configuration_changed")
        require(not any(row["Service"] not in required and row["State"] in {"running", "restarting", "paused"}
                        for row in rows), "update_runtime_mismatch")
        self.secrets_preflight(config, required | {"migrate"})
        self.tls_preflight()

    def inspect_installation(self, installed):
        config = parse_json(self.compose(["config", "--format", "json"]))
        rows = self.containers()
        running = {row["Service"] for row in rows if row["State"] == "running"}
        require(INFRA <= running and "api" in running and "backup" in running, "update_incomplete_installation")
        services = sorted(running - INFRA - AUXILIARY_INFRA)
        for name in [*services, "migrate"]:
            for mount in config["services"][name].get("volumes", []):
                target = mount["target"].rstrip("/")
                # The installer preserves these read-only plugin boundaries.
                # Core code/config overlays, including their children, stay forbidden.
                plugin_setting = {"/opt/sli/plugins": "SLI_PLUGIN_RUNTIME_DIR",
                                  "/opt/sli/plugin-locks": "SLI_PLUGIN_LOCK_DIR"}.get(target)
                plugin_mount = (plugin_setting is not None and mount.get("type") == "bind"
                                and mount.get("read_only") is True
                                and config["services"][name].get("environment", {}).get(plugin_setting) == target)
                require(not (target in {"/", "/opt", "/opt/sli"} or target.startswith("/opt/sli/"))
                        or target in {"/opt/sli/data", "/opt/sli/artifacts"} or plugin_mount,
                        "update_code_mount_forbidden")
        require(installed["image_digest"] == self.image_id(installed["image_tag"]), "update_installed_image_mismatch")
        for row in rows:
            if row["Service"] in services:
                actual = self.command(["docker", "inspect", "--format", "{{.Image}}", row["ID"]]).strip()
                require(actual == installed["image_digest"], "update_installed_image_mismatch")
                require(config["services"][row["Service"]].get("healthcheck"), "update_missing_healthcheck")
        return services

    def configuration(self, replacement=None):
        if replacement:
            raw = self.command([*self.compose_files(replacement=replacement), "config", "--format", "json"])
        else:
            raw = self.compose(["config", "--format", "json"])
        return parse_json(raw)

    def deployment_fingerprint(self, replacement=None):
        return hashlib.sha256(canonical(self.configuration(replacement))).hexdigest()

    def stop_operation(self, journal):
        # Compose run can outlive a killed host process. Fence these one-off writers
        # before retrying a checkpoint or restoring PostgreSQL.
        for action in ("migrate", "backup", "restore", "check"):
            name = f"sli-update-{action}-{journal['operation']}"
            present = self.command(["docker", "container", "ls", "--all", "--filter", f"name=^/{name}$", "--quiet"]).strip()
            if present:
                self.command(["docker", "container", "rm", "--force", name])

    def stage(self, directory, manifest, tag):
        with tempfile.TemporaryDirectory(dir=directory.parent) as temporary:
            sanitized = Path(temporary) / "image.tar"
            image_inventory(directory / manifest["image"]["path"], manifest, sanitized)
            self.command(["docker", "image", "load", "--input", str(sanitized)])
        require(self.image_id(manifest["image"]["digest"]) == manifest["image"]["digest"], "update_image_digest_mismatch")
        existing = self.command(["docker", "image", "ls", "--quiet", "--no-trunc", tag]).strip()
        require(not existing or existing == manifest["image"]["digest"], "update_candidate_tag_exists")
        self.command(["docker", "image", "tag", manifest["image"]["digest"], tag])

    def in_flight(self):
        """Read active ownership only; durable queued/retry rows are not a gate.

        Discover lease columns in the installed schema, including older releases.
        Expired leases have no owner and are recovered by the next worker version.
        Never rewrite queue state, release someone else's lease or print SQL rows.
        """
        def query(sql):
            return self.compose(["exec", "-T", "postgres", "psql", "--no-password", "--username=postgres",
                                 "--dbname=sli", "--quiet", "--no-align", "--tuples-only", "--set=ON_ERROR_STOP=1",
                                 "--command", "BEGIN READ ONLY; SET LOCAL statement_timeout='5s'; " + sql + "; COMMIT;"],
                                timeout=10).strip()

        leases = query("""SELECT coalesce(string_agg(format(
            'SELECT count(*) AS n FROM %I.%I WHERE %I > statement_timestamp()',
            n.nspname, c.relname, a.attname), ' UNION ALL '), 'SELECT 0 AS n')
            FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
            JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname IN ('public', 'sli_jobs') AND c.relkind IN ('r', 'p')
            AND NOT c.relispartition AND NOT a.attisdropped
            AND a.attname IN ('lease_until', 'worker_lease_until', 'lease_expires_at')""")
        return parse_json(query("SELECT json_build_object('leases', (SELECT coalesce(sum(n),0) FROM (" + leases +
                                ") leases), 'transactions', (SELECT count(*) FROM pg_stat_activity "
                                "WHERE datname=current_database() AND backend_type='client backend' "
                                "AND pid<>pg_backend_pid() AND xact_start IS NOT NULL))"))

    def legacy_interrupt_exit(self, journal, row, diagnostic, signalled, elapsed, budget):
        previous = journal.get("previous", {})
        addressed = row.get("ID") in signalled and signalled[row["ID"]] == row.get("Service")
        # Checkpoint and drain both verify the fence. Reuse only a successful
        # SIGINT proof from this authenticated operation, re-inspecting its state.
        prior = next((item["legacy_interrupt"] for attempt in journal.get("drain_services", [])
                      if attempt.get("stop_signal") == "SIGINT" for item in attempt.get("containers", [])
                      if item.get("Service") == row.get("Service")
                      and item.get("legacy_interrupt", {}).get("accepted") is True
                      and item["legacy_interrupt"].get("addressed_id") == row.get("ID")), None)
        if not (row.get("ExitCode") == 130 and row.get("State") == "exited"
                and row.get("Service") in INTERRUPT_SERVICES - {"api"}
                and (addressed or prior is not None)
                and previous.get("source_commit") in LEGACY_INTERRUPT_REVISIONS
                and 0 <= elapsed < budget):
            return False
        # Inspect only the addressed container, never credentials/environment.
        template = ('{"id":{{json .Id}},"image":{{json .Image}},'
                    '"revision":{{json (index .Config.Labels "org.opencontainers.image.revision")}},'
                    '"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
                    '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
                    '"status":{{json .State.Status}},"exit_code":{{.State.ExitCode}},'
                    '"started_at":{{json .State.StartedAt}},"finished_at":{{json .State.FinishedAt}},'
                    '"restart_count":{{.RestartCount}},'
                    '"oom_killed":{{.State.OOMKilled}},"error_empty":{{eq .State.Error ""}}}')
        observed = parse_json(self.command(["docker", "inspect", "--format", template, row["ID"]], timeout=10))
        # Compose may return an unambiguous short ID; inspect returns the full ID.
        observed["addressed_id"] = row["ID"]
        accepted = (observed.get("id", "").startswith(row["ID"])
                and observed.get("image") == previous.get("image_digest")
                and observed.get("revision") == previous["source_commit"]
                and observed.get("project") == "sli" and observed.get("service") == row["Service"]
                and observed.get("status") == "exited" and observed.get("exit_code") == 130
                and observed.get("oom_killed") is False and observed.get("error_empty") is True
                and (addressed or all(prior.get(key) == value for key, value in observed.items())))
        diagnostic["legacy_interrupt"] = {**observed, "accepted": accepted,
                                          "elapsed_ms": int(elapsed * 1000) if addressed else prior["elapsed_ms"]}
        return accepted

    def stop_identity(self, identifier):
        template = ('{"id":{{json .Id}},"image":{{json .Image}},'
                    '"revision":{{json (index .Config.Labels "org.opencontainers.image.revision")}},'
                    '"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
                    '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
                    '"status":{{json .State.Status}},"exit_code":{{.State.ExitCode}},'
                    '"started_at":{{json .State.StartedAt}},"finished_at":{{json .State.FinishedAt}},'
                    '"restart_count":{{.RestartCount}},"oom_killed":{{.State.OOMKilled}},'
                    '"error_empty":{{eq .State.Error ""}}}')
        return parse_json(self.command(["docker", "inspect", "--format", template, identifier], timeout=10))

    def unhandled_term(self, identifier):
        status = self.command(["docker", "exec", identifier, "cat", "/proc/1/status"], timeout=10)
        mask = re.search(r"^SigCgt:\s*([0-9a-fA-F]{16})$", status, re.MULTILINE)
        return mask.group(1) if mask and not int(mask.group(1), 16) & (1 << 14) else None

    def legacy_stopped(self, journal, row):
        """Reuse only the exact stopped incarnation attested by this operation."""
        for attempt in journal.get("drain_services", []):
            for proof in attempt.get("legacy_term_stops", []):
                if (proof.get("accepted") is True and proof.get("addressed_id") == row.get("ID")
                        and proof.get("after", {}).get("service") == row.get("Service")
                        and row.get("State") == "exited" and row.get("ExitCode") == 137
                        and self.stop_identity(row["ID"]) == proof["after"]):
                    return True
        return False

    def legacy_term_stop(self, journal, row, attempt, deadline):
        previous = journal.get("previous", {})
        if (previous.get("source_commit") not in LEGACY_INTERRUPT_REVISIONS
                or row.get("Service") != "api" or row.get("State") != "running"):
            return False
        before = self.stop_identity(row["ID"])
        if not (before.get("id", "").startswith(row["ID"])
                and before.get("image") == previous.get("image_digest")
                and before.get("revision") == previous["source_commit"]
                and before.get("project") == "sli" and before.get("service") == row["Service"]
                and before.get("status") == "running" and before.get("oom_killed") is False
                and before.get("error_empty") is True):
            return False
        mask = self.unhandled_term(row["ID"])
        if mask is None:
            return False
        budget = min(25, int(deadline - time.monotonic()) - 10)
        require(budget > 0, "update_drain_service_timeout")
        proof = {"addressed_id": row["ID"], "before": before, "sigcgt": mask,
                 "stop_signal": "SIGINT", "timeout_seconds": budget, "accepted": False}
        attempt.setdefault("legacy_term_stops", []).append(proof)
        attempt["addressed_containers"] = [{"ID": row["ID"], "Service": row["Service"]}]
        attempt["stop_pending"] = True
        self.persist_drain(journal)
        started = time.monotonic()
        try:
            # SIGINT closes the old API listener even if Python's thread joins
            # hang at exit. Docker suppresses restart, but may not auto-kill.
            self.command(["docker", "container", "stop", "--signal", "SIGINT", "--time", "-1", row["ID"]],
                         timeout=budget)
        except subprocess.TimeoutExpired:
            proof["soft_wait_expired"] = True
        observed = self.stop_identity(row["ID"])
        # A successful stop RPC is not a stopped-container proof (the stand
        # journal recorded running/0). Independently observe the full grace.
        while observed.get("status") == "running" and time.monotonic() < started + budget:
            time.sleep(min(1, max(0, started + budget - time.monotonic())))
            observed = self.stop_identity(row["ID"])
        proof["elapsed_ms"] = int((time.monotonic() - started) * 1000)
        if observed.get("status") == "exited" and observed.get("exit_code") == 0:
            require(all(observed.get(key) == before.get(key) for key in (
                "id", "image", "revision", "project", "service", "started_at", "restart_count"))
                and observed.get("oom_killed") is False and observed.get("error_empty") is True,
                "update_drain_service_timeout")
            proof["after"] = observed
            attempt["stop_pending"] = False
            return True
        # Check the same incarnation and handler again immediately before force.
        require(observed == before and proof["elapsed_ms"] >= budget * 1000
                and self.unhandled_term(row["ID"]) is not None, "update_drain_service_timeout")
        while True:
            active = self.in_flight()
            proof["in_flight"] = active
            if not active["leases"] and not active["transactions"]:
                break
            require(deadline - time.monotonic() > 10,
                    "update_drain_lease_timeout" if active["leases"] else "update_drain_transaction_timeout")
            time.sleep(min(1, max(0, deadline - time.monotonic() - 10)))
        # Waiting for ownership can outlive the original incarnation/handler.
        require(self.stop_identity(row["ID"]) == before and self.unhandled_term(row["ID"]) is not None,
                "update_drain_service_timeout")
        require(deadline - time.monotonic() >= 5, "update_drain_service_timeout")
        proof["force_signal"] = "SIGKILL"
        # The real host persists authenticated intent before the external effect.
        self.persist_drain(journal)
        self.command(["docker", "kill", "--signal", "SIGKILL", row["ID"]], timeout=5)
        self.command(["docker", "wait", row["ID"]], timeout=min(5, max(1, deadline - time.monotonic())))
        after = self.stop_identity(row["ID"])
        proof["after"] = after
        proof["accepted"] = (all(after.get(key) == before.get(key) for key in (
            "id", "image", "revision", "project", "service", "started_at", "restart_count"))
            and after.get("status") == "exited" and after.get("exit_code") == 137
            and after.get("oom_killed") is False and after.get("error_empty") is True)
        self.persist_drain(journal)
        require(proof["accepted"], "update_drain_service_timeout")
        attempt["stop_pending"] = False
        return True

    def wait_stopped(self, attempt, deadline):
        """A timed-out CLI does not cancel the daemon's outstanding stop RPC."""
        addressed = {row["ID"]: row["Service"] for row in attempt.get("addressed_containers", [])}
        while addressed:
            try:
                rows = {row["ID"]: row for row in self.containers() if row.get("ID") in addressed}
            except Exception:
                attempt["failure_reason"] = "readback_unavailable"
                attempt["failure_resolved"] = False
                attempt["failed_services"] = []  # No evidence which service failed to stop.
                raise
            unknown = [service for key, service in addressed.items()
                       if key not in rows or rows[key]["Service"] != service]
            if unknown:
                attempt.update(failed_services=sorted(set(unknown))[:128],
                               failure_reason="container_identity_unverified", failure_resolved=False)
                raise UpdateError("update_drain_service_timeout")
            running = [row["Service"] for row in rows.values() if row["State"] in {"running", "restarting", "paused"}]
            if not running:
                attempt["stop_pending"] = False
                if attempt.get("failure_reason"):
                    attempt["failure_resolved"] = True
                return
            if time.monotonic() >= deadline:
                attempt.update(failed_services=sorted(set(running))[:128], failure_reason="still_running", failure_resolved=False)
                raise UpdateError("update_drain_service_timeout")
            time.sleep(min(1, max(0, deadline - time.monotonic())))

    def settle_stops(self, journal):
        # Never restart an incarnation which a previous stop can still terminate.
        # Recovery may retry this read-only wait; it must not force a busy writer.
        deadline = time.monotonic() + self.drain_timeout
        for attempt in journal.get("drain_services", []):
            if attempt.get("stop_pending"):
                self.wait_stopped(attempt, deadline)
                self.persist_drain(journal)

    def backup_activity(self):
        # Inject a stdlib-only probe: the installed image may predate this module.
        source = Path(__file__).with_name("backup_activity.py").read_text("utf-8")
        return parse_json(self.compose(["exec", "-T", "backup", "python", "-c", source], timeout=10))

    def wait_backup_idle(self, journal, deadline):
        if not any(row["Service"] == "backup" and row["State"] == "running" for row in self.containers()):
            return
        while True:
            state = self.backup_activity()
            require(type(state.get("busy")) is bool, "update_backup_activity_unavailable")
            if not state["busy"]:
                upcoming = state.get("next_backup_at_utc")
                if upcoming is not None:
                    # Do not race the scheduler when verification reached the
                    # next slot. Leave enough time for the bounded soft stops.
                    scheduled = datetime.fromisoformat(upcoming)
                    require(scheduled.tzinfo is not None, "update_backup_activity_unavailable")
                    require((scheduled - datetime.now(timezone.utc)).total_seconds() > self.drain_timeout,
                            "update_backup_busy")
                return
            journal["backup_wait"] = "running"
            self.persist_drain(journal)
            require(time.monotonic() < deadline, "update_backup_busy")
            time.sleep(min(5, max(0, deadline - time.monotonic())))

    def drain(self, journal):
        override = self.operation_override(journal, "previous_override")
        deadline = time.monotonic() + self.drain_timeout
        # Preflight/restore verification can last hours and cross the nightly
        # slot. Wait before touching ingress or any writer; never kill a dump.
        self.wait_backup_idle(journal, deadline)
        # Waiting for a copy must not consume the writers' shutdown budget.
        deadline = time.monotonic() + self.drain_timeout
        # Close ingress before signalling workers. New workers finish their
        # current batch on either signal without emptying the durable backlog.
        groups = [["api"]] if "api" in journal["services"] else []
        groups.append([name for name in journal["services"] if name in INTERRUPT_SERVICES and name != "api"])
        groups.append([name for name in journal["services"] if name not in INTERRUPT_SERVICES])
        if journal.get("previous", {}).get("source_commit") in LEGACY_INTERRUPT_REVISIONS and "api" in journal["services"]:
            # The verified old workers exit 130 on SIGINT. Stop those writers
            # before considering API force, otherwise their active transactions
            # would veto it. Ingress remains durable queued work until API stops;
            # no backlog is discarded. New releases keep API-first soft shutdown.
            groups.append(groups.pop(0))
        for services in groups:
            if not services:
                continue
            remaining = int(deadline - time.monotonic())
            require(remaining > 0, "update_drain_service_timeout")
            remaining = min(remaining, 25)
            attempt = {"services": services, "timeout_seconds": remaining}
            journal.setdefault("drain_services", []).append(attempt)
            signalled = {}
            started = time.monotonic()
            stop_budget = deadline - started
            try:
                handled = {row["ID"] for row in self.containers() if row["Service"] in services
                           and self.legacy_term_stop(journal, row, attempt, deadline)}
                remaining = min(25, int(deadline - time.monotonic()))
                require(remaining > 0, "update_drain_service_timeout")
                if services[0] in INTERRUPT_SERVICES:
                    # Older Python PID 1 images catch SIGINT but ignore SIGTERM.
                    # docker stop suppresses restart policies, unlike docker kill.
                    attempt["stop_signal"] = "SIGINT"
                    before = self.containers()
                    ids = [row["ID"] for row in before
                           if row["Service"] in services and row.get("ID") not in handled
                           and row["State"] in {"running", "restarting", "paused"}]
                    if ids:
                        addressed = {row["ID"]: row["Service"] for row in before
                                     if row["ID"] in ids and row["State"] == "running"}
                        signalled = addressed
                        attempt["addressed_containers"] = [{"ID": row["ID"], "Service": row["Service"]}
                                                            for row in before if row["ID"] in ids]
                        attempt["stop_pending"] = True
                        self.persist_drain(journal)
                        try:
                            self.command(["docker", "container", "stop", "--signal", "SIGINT",
                                          "--time", "-1", *ids], timeout=remaining)
                        except subprocess.TimeoutExpired:
                            attempt["command_timed_out"] = True
                        self.wait_stopped(attempt, deadline)
                else:
                    before = [row for row in self.containers()
                              if row["Service"] in services and row["State"] in {"running", "restarting", "paused"}]
                    pending = [row["Service"] for row in before]
                    if pending:
                        attempt["addressed_containers"] = [{"ID": row["ID"], "Service": row["Service"]} for row in before]
                        attempt["stop_pending"] = True
                        self.persist_drain(journal)
                        try:
                            self.compose(["stop", "--timeout", "-1", *pending], override, timeout=remaining)
                        except subprocess.TimeoutExpired:
                            attempt["command_timed_out"] = True
                        self.wait_stopped(attempt, deadline)
            except subprocess.TimeoutExpired:
                attempt["command_timed_out"] = True
                raise UpdateError("update_drain_service_timeout") from None
            finally:
                attempt["elapsed_ms"] = int((time.monotonic() - started) * 1000)
                try:
                    stopped = [row for row in self.containers() if row["Service"] in services]
                    attempt["containers"] = [{key: row.get(key) for key in ("Service", "State", "ExitCode")}
                                             for row in stopped]
                except Exception:  # Diagnostics must not obscure the stop failure.
                    attempt["containers_unavailable"] = True
            elapsed = time.monotonic() - started
            require("containers" in attempt, "update_drain_service_timeout")
            for row, diagnostic in zip(stopped, attempt["containers"]):
                accepted = row["State"] not in {"running", "restarting", "paused"} and (
                    row["ExitCode"] == 0 or self.legacy_stopped(journal, row) or self.legacy_interrupt_exit(
                        journal, row, diagnostic, signalled, elapsed, stop_budget))
                if not accepted:
                    attempt.update(failed_services=[row["Service"]], failure_reason=("still_running"
                        if row["State"] in {"running", "restarting", "paused"} else "exit_code"), failure_resolved=False)
                    raise UpdateError("update_drain_service_timeout")
        rows = self.containers()
        require(not any(row["Service"] not in (INFRA | AUXILIARY_INFRA) and row["State"] in {"running", "restarting", "paused"}
                        for row in rows), "update_drain_service_timeout")
        require(not any(row["Service"] in journal["services"] and row.get("ExitCode") == 137
                        and not self.legacy_stopped(journal, row) for row in rows),
                "update_drain_service_timeout")
        while True:
            active = self.in_flight()
            journal["drain_in_flight"] = active
            if not active["leases"] and not active["transactions"]:
                return
            require(time.monotonic() < deadline,
                    "update_drain_lease_timeout" if active["leases"] else "update_drain_transaction_timeout")
            time.sleep(min(1, max(0, deadline - time.monotonic())))

    def helper(self, journal, action, identifier):
        # Host-owned source, using only the previous trusted image and its credentials.
        source = Path(__file__).with_name("update_checkpoint.py").read_text("utf-8")
        override = self.operation_override(journal, "previous_override")
        backup_source = Path(__file__).with_name("backup.py").read_text("utf-8")
        restore_source = Path(__file__).with_name("restore_existing.py").read_text("utf-8")
        readback_source = Path(__file__).with_name("backup_restore_check.py").read_text("utf-8")
        policy_source = Path(__file__).with_name("backup_policy.py").read_text("utf-8")
        sandbox_source = Path(__file__).with_name("restore_sandbox.py").read_text("utf-8")
        # The previous image may still contain the old disk-path mapping. Load
        # host-owned helpers there; never use candidate/package code.
        source = (helper_preload_source(policy_source, sandbox_source) +
                  "from deploy.linux import backup\n"
                  f"exec({backup_source!r}, backup.__dict__)\n"
                  "from deploy.linux import backup_restore_check\n"
                  f"exec({readback_source!r}, backup_restore_check.__dict__)\n"
                  "from deploy.linux import restore_existing\n"
                  f"exec({restore_source!r}, restore_existing.__dict__)\n"
                  "from deploy.linux import update_checkpoint\n"
                  f"exec({source!r}, update_checkpoint.__dict__)\n"
                  "raise SystemExit(update_checkpoint.main())")
        self.stop_operation(journal)
        # Keep verified restore inputs on disk outside shared backup mounts and
        # the memory-limited /tmp tmpfs. Only this one-off helper sees this bind.
        with tempfile.TemporaryDirectory(dir=journal["directory"], prefix="checkpoint-") as temporary:
            if os.name != "nt":
                os.chown(temporary, 10001, 10001)  # Trusted backup image's sli identity.
            return self.compose(["run", "--rm", "--name", f"sli-update-{action}-{journal['operation']}",
                                 "--no-deps", "-T", "--entrypoint", "python",
                                 "--volume", f"{temporary}:/update-snapshot",
                                 "--env", "SLI_UPDATE_SNAPSHOT_ROOT=/update-snapshot",
                                 # Program via stdin: the joined trusted sources exceed
                                 # Linux's 128 KiB single-argument limit (E2BIG).
                                 "backup", "-", action, identifier], override,
                                stdin=source.encode("utf-8"))

    def checkpoint(self, journal):
        identity = {key: journal[key] for key in ("operation", "checkpoint_key")}
        identity["recovery_profile"] = journal["manifest"].get("recovery_profile", "full")
        identity["daily_backup"] = journal.get("daily_backup")
        result = parse_json(self.helper(journal, "backup", canonical(identity).decode("ascii")))
        require(result.get("status") != "waiting", "update_fresh_daily_backup_required")
        return result

    def check_backup(self, journal):
        identity = {key: journal[key] for key in ("operation", "checkpoint_key")}
        result = parse_json(self.helper(journal, "check", canonical(identity).decode("ascii")))
        require(result.get("status") == "verified", "update_fresh_daily_backup_required")
        selected = result["daily_backup"]
        # A daily set predating another schema update cannot restore this release.
        require(selected["migration_ledger_max_version"] == max(
            row["version"] for row in journal["previous"]["migration_ledger"]), "update_daily_backup_schema_mismatch")
        from deploy.linux.installed_state import installation_key, inventory

        registry = selected.get("installed_release")
        if registry is not None:
            require(isinstance(registry, dict)
                    and registry.get("installation_key") == installation_key(journal["previous"]),
                    "update_daily_backup_schema_mismatch")
            saved = registry.get("inventory", {})
            expected = inventory(journal["previous"])
            require(all(saved.get(key) == expected[key] for key in ("migration_ledger", "plugins")),
                    "update_daily_backup_schema_mismatch")
        journal["daily_backup"] = selected
        journal["backup_verification"] = "nightly"

    def migrate(self, journal):
        override = self.operation_override(journal, "candidate_override")
        self.stop_operation(journal)
        require(self.image_id(journal["candidate_tag"]) == journal["manifest"]["image"]["digest"], "update_image_digest_mismatch")
        self.compose(["run", "--rm", "--name", f"sli-update-migrate-{journal['operation']}",
                      "--no-deps", "-T", "migrate"], override)

    def activate(self, journal, previous=False):
        override = self.operation_override(journal, "previous_override" if previous else "candidate_override")
        reference = journal["previous"]["image_tag"] if previous else journal["candidate_tag"]
        expected = journal["previous"]["image_digest"] if previous else journal["manifest"]["image"]["digest"]
        require(self.image_id(reference) == expected, "update_image_digest_mismatch")
        if previous and journal.get("added_services"):
            candidate = self.operation_override(journal, "candidate_override")
            self.compose(["stop", "--timeout", "-1", *journal["added_services"]], candidate, timeout=60)
            rows = [row for row in self.containers() if row["Service"] in journal["added_services"]]
            require(all(row["State"] == "exited" and row.get("ExitCode") != 137 for row in rows),
                    "update_stop_incomplete")
            self.compose(["rm", "-f", *journal["added_services"]], candidate)
        def start(services):
            if services:
                self.compose(["up", "-d", "--no-deps", "--no-build", "--pull", "never", *services], override)

        if previous and "api" in journal["services"]:
            # Keep ingress closed until every background service has the old
            # image. Compose itself recreates containers sequentially, not atomically.
            workers = set(journal["services"]) - {"api"}
            start(sorted(workers))
            rows = [row for row in self.containers() if row["Service"] in workers]
            require(workers <= {row["Service"] for row in rows if row["State"] == "running"}, "update_runtime_mismatch")
            for row in rows:
                actual = self.command(["docker", "inspect", "--format", "{{.Image}}", row["ID"]]).strip()
                require(actual == expected, "update_runtime_mismatch")
            start(["api"])
        else:
            start(active_services(journal, previous))

    def health(self, journal, *, backup_waiver=None):
        # An invocation-scoped exception, never a sticky host or journal setting.
        if backup_waiver is not None:
            require(backup_waiver in {"previous", "candidate"}, "update_backup_waiver_not_allowed")
            require(journal.get("component", "server") == "server", "update_backup_waiver_not_allowed")
            require(journal.get("migration_started") is (backup_waiver == "candidate"),
                    "update_backup_waiver_not_allowed")
        deadline = time.monotonic() + self.timeout
        previous = journal.get("status") == "rolling_back"
        expected = {*active_services(journal, previous), *INFRA}
        if backup_waiver is not None:
            require((backup_waiver == "previous") == previous and "backup" in expected,
                    "update_backup_waiver_not_allowed")
            image = (journal["previous"]["image_digest"] if previous else journal["manifest"]["image"]["digest"])
            require(isinstance(image, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", image),
                    "update_runtime_mismatch")
        context = ssl.create_default_context(cafile=str(self.ca_file))
        while time.monotonic() < deadline:
            if backup_waiver is not None:
                require(journal.get("migration_started") is (backup_waiver == "candidate"),
                        "update_backup_waiver_not_allowed")
            rows = self.containers()
            healthy = {row["Service"] for row in rows if row["State"] == "running" and row.get("Health") == "healthy"}
            check = expected
            evidence = None
            if backup_waiver is not None:
                backups = [row for row in rows if row["Service"] == "backup"]
                if (len(backups) == 1 and backups[0]["State"] == "running"
                        and backups[0].get("Health") in {"healthy", "unhealthy", "starting"}):
                    actual = self.command(["docker", "inspect", "--format", "{{.Image}}", backups[0]["ID"]]).strip()
                    require(actual == image, "update_runtime_mismatch")
                    check = expected - {"backup"}
                    evidence = {"backup_health": "healthy" if backups[0]["Health"] == "healthy" else "operator_waived",
                                "observed_health": backups[0]["Health"], "image_digest": actual}
                else:
                    # Missing, stopped or ambiguous containers are not a health waiver.
                    time.sleep(2)
                    continue
            if check <= healthy and all(row["State"] == "running" and row.get("Health") == "healthy"
                                        for row in rows if row["Service"] in check):
                try:
                    with urlopen(self.health_url, context=context, timeout=5) as response:
                        if response.status == 200:
                            return evidence
                except OSError:
                    pass
            time.sleep(2)
        raise UpdateError("update_health_timeout")

    def restore(self, journal):
        identity = {key: journal[key] for key in ("operation", "backup_id", "checkpoint_sha256", "checkpoint_key")}
        self.helper(journal, "restore", canonical(identity).decode("ascii"))

    def fence(self, journal):
        """Stop application writers after failed recovery; never stop data services.

        This is containment, not a successful graceful drain. A stuck old API
        must not keep a partially restored release serving requests.
        """
        override = self.operation_override(journal, "previous_override")
        try:
            self.compose(["stop", "--timeout", "10", *active_services(journal)], override, timeout=20)
        except Exception:
            pass  # Read back and force-stop only the remaining owned containers.
        active = {"running", "restarting", "paused"}
        rows = [row for row in self.containers() if row["Service"] not in (INFRA | AUXILIARY_INFRA) and row["State"] in active]
        require(all(row["Service"] in active_services(journal) for row in rows), "update_rollback_foreign_services")
        for row in rows:
            try:
                self.command(["docker", "container", "stop", "--time", "0", row["ID"]], timeout=15)
            except Exception:
                pass  # Attempt every writer even when one stop fails; readback is authoritative.
        require(not any(row["Service"] not in (INFRA | AUXILIARY_INFRA) and row["State"] in active for row in self.containers()),
                "update_rollback_fence_failed")

    def recovery_health(self, journal):
        """Console rollback readback without HTTPS or application readiness claims."""
        deadline = time.monotonic() + self.timeout
        expected = {*journal["services"], *INFRA}
        while time.monotonic() < deadline:
            rows = self.containers()
            running = {row["Service"] for row in rows if row["State"] == "running"}
            healthy_data = {row["Service"] for row in rows if row["State"] == "running" and row.get("Health") == "healthy"}
            if expected <= running and INFRA <= healthy_data and all(
                row["State"] == "running" for row in rows if row["Service"] in expected
            ):
                for row in rows:
                    if row["Service"] in journal["services"]:
                        actual = self.command(["docker", "inspect", "--format", "{{.Image}}", row["ID"]]).strip()
                        require(actual == journal["previous"]["image_digest"], "update_installed_image_mismatch")
                return
            time.sleep(2)
        raise UpdateError("update_recovery_readback_failed")


class Updater:
    def __init__(self, runtime, trust_store, host):
        require_complete_updater()
        self.runtime, self.trust_store, self.host = Path(runtime), Path(trust_store), host
        self.state = self.runtime / "state"
        self.journal_path = self.state / "update-journal.json"
        self.installed_path = self.state / "installed.json"
        self.reconciliation_path = self.state / "ledger-reconciliation.json"
        if hasattr(host, "persist_drain"):
            host.persist_drain = self.save

    def journal_key(self):
        protected_path(self.state, directory=True)
        key = self.state / "update-journal.key"
        if not key.exists() and not key.is_symlink():
            # This directory is host-owned and 0700, never mounted in app containers.
            descriptor = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(os.urandom(32))
                stream.flush()
                os.fsync(stream.fileno())
        protected_path(key)
        if os.name != "nt":
            require(key.stat().st_mode & 0o077 == 0, "update_unsafe_state")
        with key.open("rb") as stream:
            value = stream.read(33)
        require(len(value) == 32, "update_unsafe_state")
        return value

    def read_journal(self, path):
        protected_path(path)
        journal = parse_json(path.read_bytes())
        signature = journal.pop("authentication", None)
        require(isinstance(signature, str) and hmac.compare_digest(
            signature, hmac.digest(self.journal_key(), canonical(journal), "sha256").hex()),
            "update_journal_authentication_failed")
        return journal

    def save(self, journal, *, path=None):
        journal = {key: value for key, value in journal.items() if key != "authentication"}
        signature = hmac.digest(self.journal_key(), canonical(journal), "sha256").hex()
        atomic_json(path or self.journal_path, {**journal, "authentication": signature})

    def require_volume_reconciled(self):
        path = self.state / "volume-reconciliation.json"
        if path.exists():
            require(self.read_journal(path).get("status") == "committed", "update_volume_reconciliation_required")

    def reconcile_volumes(self, operation_id, *, dry_run=False):
        """Repair only an attested services-only publication; never create storage."""
        require(isinstance(operation_id, str) and re.fullmatch(r"[a-f0-9]{32}", operation_id),
                "update_invalid_operation")
        with operation_lock(self.state):
            latest = self.read_journal(self.journal_path)
            require(latest["status"] in {"committed", "rolled_back", "rejected"}, "update_resume_required")
            evidence_path = self.state / "updates" / operation_id / "journal.json"
            evidence = self.read_journal(evidence_path)
            target = self.state / "install-compose.json"
            protected_path(target)
            protected_path(self.installed_path)
            installed = parse_json(self.installed_path.read_bytes())
            switch = evidence.get("notification_compose_switch") or {}
            require(evidence.get("operation") == operation_id and evidence.get("status") == "committed"
                    and evidence.get("phase") == "commit" and evidence.get("completed") == list(PHASES)
                    and switch.get("acknowledged") is True and switch.get("path") == str(target),
                    "update_volume_reconciliation_unattested")
            require(installed == self.candidate(evidence) and installed.get("compose_project") == "sli",
                    "update_installed_state_changed")
            source = Path(checked_override(evidence, "candidate_override"))
            require(source == evidence_path.parent / "candidate.json" and str(source) == installed.get("override")
                    and sha256(source) == switch.get("after"), "update_volume_reconciliation_unattested")
            partial = parse_json(source.read_bytes())
            require(not partial.get("volumes") and "notification-delivery" in partial.get("services", {}),
                    "update_volume_reconciliation_unattested")
            names = installed.get("volumes")
            require(isinstance(names, dict) and names and len(set(names.values())) == len(names)
                    and all(isinstance(key, str) and isinstance(name, str)
                            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name) for key, name in names.items()),
                    "update_volume_ownership")
            files = {str(path): sha256(path) for path in self.host.files}
            recorded = evidence["compose_files"]
            require(set(files) == set(recorded) and str(target) in files
                    and all(files[path] == checksum for path, checksum in recorded.items() if path != str(target)),
                    "update_compose_changed")
            require(recorded[str(target)] == switch["after"], "update_volume_reconciliation_unattested")
            path = self.state / "volume-reconciliation.json"
            intent = self.read_journal(path) if path.exists() else None
            if intent is None:
                require(files[str(target)] == switch["after"] and target.read_bytes() == source.read_bytes()
                        and self.host.deployment_fingerprint() == switch.get("fingerprint"),
                        "update_compose_changed")
                current = self.host.configuration()
                require(set(current.get("volumes", {})) == set(names)
                        and {key: value["name"] for key, value in current["volumes"].items()} != names,
                        "update_volume_ownership")
                proposed = dict(partial, volumes={key: {"name": name, "external": True} for key, name in names.items()})
                intent = {"format_version": 1, "operation": operation_id, "status": "prepared",
                          "evidence_sha256": sha256(evidence_path), "installed_sha256": sha256(self.installed_path),
                          "compose_files": recorded, "before": files[str(target)],
                          "before_bytes": base64.b64encode(target.read_bytes()).decode("ascii"),
                          "after": hashlib.sha256(canonical(proposed)).hexdigest(), "proposed": proposed,
                          "before_fingerprint": switch["fingerprint"]}
            require(intent.get("operation") == operation_id and intent.get("status") in {"prepared", "committed"}
                    and intent.get("evidence_sha256") == sha256(evidence_path)
                    and intent.get("installed_sha256") == sha256(self.installed_path)
                    and intent.get("compose_files") == recorded and intent.get("before") == switch["after"]
                    and base64.b64decode(intent["before_bytes"], validate=True) == source.read_bytes()
                    and hashlib.sha256(canonical(intent["proposed"])).hexdigest() == intent["after"]
                    and files[str(target)] in {intent["before"], intent["after"]},
                    "update_volume_reconciliation_changed")
            require(intent["status"] != "committed" or files[str(target)] == intent["after"],
                    "update_volume_reconciliation_changed")
            # The existing external-volume guard also allows unlabelled volumes.
            # This repair is narrower: every attested object must already be ours.
            for name in names.values():
                labels = parse_json(self.host.command(["docker", "volume", "inspect", "--format", "{{json .Labels}}", name]))
                require(labels and labels.get("com.docker.compose.project") == "sli", "update_volume_ownership")
            with tempfile.TemporaryDirectory(dir=self.state) as temporary:
                staged = Path(temporary) / "install-compose.json"
                atomic_json(staged, intent["proposed"])
                replacement = {str(target): staged}
                config = self.host.configuration(replacement)
                self.host.ownership_preflight(installed, config)
                fingerprint = self.host.deployment_fingerprint(replacement)
                require(intent.get("after_fingerprint", fingerprint) == fingerprint,
                        "update_configuration_changed")
                expected = intent["before_fingerprint"] if files[str(target)] == intent["before"] else fingerprint
                require(self.host.deployment_fingerprint() == expected, "update_configuration_changed")
                if dry_run:
                    return "dry_run"
                if intent["status"] == "committed":
                    return "reconciled"
                intent["after_fingerprint"] = fingerprint
                self.save(intent, path=path)  # Authenticated intent precedes metadata publication.
                require(sha256(target) == files[str(target)] and sha256(self.installed_path) == intent["installed_sha256"],
                        "update_volume_reconciliation_changed")
                atomic_json(target, intent["proposed"])
                require(sha256(target) == intent["after"] and self.host.deployment_fingerprint() == fingerprint,
                        "update_configuration_changed")
                self.host.ownership_preflight(installed, self.host.configuration())
                intent["status"] = "committed"
                self.save(intent, path=path)
                return "reconciled"

    def reconcile(self, package, *, dry_run=False):
        """Attest already applied SQL against a signed image; never execute SQL migrations.

        Keep the deployed image's inventory intact. Only its exact database ledger
        attestation is refreshed, through the normal guarded registry transaction.
        An authenticated intent makes retry after DB commit/cache failure safe.
        """
        from deploy.linux.installed_state import registry_matches, validate

        with operation_lock(self.state):
            self.require_volume_reconciled()
            if self.journal_path.exists():
                require(self.read_journal(self.journal_path)["status"] in {"committed", "rolled_back", "rejected"},
                        "update_resume_required")
            protected_path(self.installed_path)
            installed = parse_json(self.installed_path.read_bytes())
            intent = self.read_journal(self.reconciliation_path) if self.reconciliation_path.exists() else None
            pending = intent is not None and intent["status"] != "committed"
            previous = intent["previous"] if pending else installed
            verified = self.verified(package, previous)
            manifest = verified.manifest
            require(manifest["component"] == "server" and manifest.get("recovery_profile", "full") == "full",
                    "update_reconciliation_requires_core")
            if pending:
                require(verified.archive_sha256 == intent["package_sha256"]
                        and installed in (previous, intent["candidate"]), "update_reconciliation_changed")
            observed = self.host.preflight(previous, manifest)
            require(observed.get("installed_release_available") is not False, "update_installed_registry_required")
            actual = observed.get("migration_ledger", [])
            require(isinstance(actual, list) and actual and all(isinstance(row, dict)
                    and type(row.get("version")) is int for row in actual), "update_migration_ledger_mismatch")
            original = previous["migration_ledger"]
            maximum = max(row["version"] for row in original)
            # Existing entries must remain byte-for-byte identical, including
            # their historical hashes. Only later versions can be reconciled.
            require([row for row in actual if row["version"] <= maximum] == original,
                    "update_migration_ledger_mismatch")
            require(observed["migration_ledger_max"] == manifest["compatibility"].get("migration_ledger_max"),
                    "update_migration_ledger_mismatch")
            candidate = dict(previous, migration_ledger=actual)
            validate(candidate, observed, self.runtime, registry=False)
            with tempfile.TemporaryDirectory(dir=self.state) as temporary:
                directory = Path(temporary)
                extract_payload(verified, directory / "payload")
                admitted = image_inventory(directory / "payload" / manifest["image"]["path"], manifest,
                                           directory / "image.tar", applied_ledger=actual)
            admitted = {row["version"]: row for row in admitted}
            require(all(admitted.get(row["version"]) == row for row in actual if row["version"] > maximum),
                    "update_migration_ledger_mismatch")
            if pending:
                require(candidate == intent["candidate"], "update_reconciliation_changed")
                registry = observed.get("installed_release")
                if registry and registry.get("operation") == intent["operation"]:
                    registry_matches(candidate, observed)
                else:
                    registry_matches(previous, observed)
            else:
                registry_matches(previous, observed)
            if dry_run:
                return "verified"
            if candidate == previous and not pending:
                return "reconciled"
            if not pending:
                intent = {"format_version": 1, "operation": uuid.uuid4().hex, "status": "running",
                          "previous": previous, "candidate": candidate, "package_sha256": verified.archive_sha256}
                self.save(intent, path=self.reconciliation_path)
            self.publish(intent, candidate)
            self.save({**intent, "status": "committed"}, path=self.reconciliation_path)
            return "reconciled"

    def verify(self, package, installed):
        return self.verified(package, installed).manifest

    def verified(self, package, installed):
        require(not self.trust_store.resolve().is_relative_to((self.state / "updates").resolve()), "update_package_trust_forbidden")
        if verify_package(package, self.trust_store).manifest.get("component") == "plugin":
            from deploy.linux.plugin_update import verify
            return verify(self, package, installed)
        require(installed.get("migrations") and installed.get("image_tag")
                and isinstance(installed.get("image_digest"), str) and installed["image_digest"].startswith("sha256:"),
                "update_installed_inventory_required")
        return verify_package(package, self.trust_store, installed=installed, free_bytes=shutil.disk_usage(self.state).free)

    def operation(self, operation_id=None):
        if operation_id is not None:
            require(re.fullmatch(r"[a-f0-9]{32}", operation_id), "update_invalid_operation")
        require(self.journal_path.is_file(), "update_operation_not_found")
        journal = self.read_journal(self.journal_path)
        if operation_id is None or journal["operation"] == operation_id:
            return journal
        archived = self.state / "updates" / operation_id / "journal.json"
        require(archived.is_file(), "update_operation_not_found")
        result = self.read_journal(archived)
        require(result["operation"] == operation_id and result["status"] in {"committed", "rolled_back", "rejected"},
                "update_invalid_journal")
        return result

    def preflight(self, installed, manifest):
        from deploy.linux.installed_state import validate
        required = max(manifest["required_free_disk"], 3 * sum(item["size"] for item in manifest["files"]))
        require(shutil.disk_usage(self.state).free >= required, "update_insufficient_disk")
        observed = self.host.preflight(installed, manifest)
        if observed.get("installed_release_available") is False:
            require(any(re.match(r"179_", Path(path).name) for path in manifest["migrations"]),
                    "update_installed_registry_required")
        expected = manifest["compatibility"]
        require({"migration_ledger_max", "plugins"} <= set(expected), "update_preflight_expectations_required")
        ledger_max = max((row["version"] for row in installed.get("migration_ledger", [])), default=0)
        require(observed["migration_ledger_max"] == expected["migration_ledger_max"] == ledger_max,
                "update_migration_ledger_mismatch")
        inventory_max = max((int(Path(path).name.split("_", 1)[0]) for path in installed["migrations"]
                             if Path(path).name.split("_", 1)[0].isdigit()), default=0)
        incoming_versions = {int(Path(path).name.split("_", 1)[0]) for path in manifest["migrations"]
                             if Path(path).name.split("_", 1)[0].isdigit()
                             and not re.search(r"(?:\.rollback|_rollback)\.sql$", path)}
        require(all(row["version"] <= inventory_max or row["version"] in incoming_versions
                    for row in installed["migration_ledger"]), "update_migration_ledger_mismatch")
        validate(installed, observed, self.runtime)
        require(observed["services"] and all(runtime_version_matches(value["version"], installed)
                and value["image_digest"] == installed["image_digest"] and value["image_tag"] == installed["image_tag"]
                for value in observed["services"].values()), "update_running_version_mismatch")
        for plugin in observed["plugins"]:
            if not plugin["installed"] and not plugin["enabled"]:
                continue
            policy = expected["plugins"].get(plugin["plugin_id"])
            require(policy is not None and plugin["installed"]
                    and _version(policy["min_version"]) <= _version(plugin["version"]) <= _version(policy["max_version"])
                    and (not plugin["enabled"] or policy["enabled"]), "update_plugin_incompatible")
        return observed

    def publish(self, journal, candidate, *, previous=None):
        """DB commit precedes the cache; authenticated intent makes retries idempotent."""
        from deploy.linux.installed_state import (
            inventory, ledger_matches, plugins_match, pointers_match, registry_matches, validate,
        )
        previous = previous or journal["previous"]
        observed = self.host.observe()
        ledger_matches(candidate, observed)
        registry = observed.get("installed_release")
        targets = (journal["previous"], previous, candidate)
        nightly = journal.get("daily_backup", {}).get("installed_release")
        if journal.get("rollback_restored") and journal.get("daily_backup") and nightly is None and registry:
            # Legacy nightly receipts did not record the registry. Only after a
            # hash-verified restore may its live readback supply that evidence.
            from deploy.linux.installed_state import installation_key

            saved = registry.get("inventory", {})
            expected = inventory(journal["previous"])
            require(registry.get("installation_key") == installation_key(journal["previous"])
                    and all(saved.get(key) == expected[key] for key in ("migration_ledger", "plugins")),
                    "update_installed_registry_mismatch")
            nightly = {"installation_key": registry["installation_key"], "inventory": saved}
            journal["daily_backup"]["installed_release"] = nightly
            self.save(journal)
        if journal.get("rollback_restored") and nightly:
            # A second core update may roll back to the same nightly DB. Its
            # registry describes the night's core image, with the same ledger/plugins.
            targets += ({**journal["previous"], **nightly["inventory"]},)
        if registry:
            matched = next((target for target in targets if inventory(target) == registry.get("inventory")), None)
            require(matched is not None, "update_installed_registry_mismatch")
            if inventory(matched) != inventory(journal["previous"]) and not (
                    journal.get("rollback_restored") and nightly == {
                        "installation_key": registry.get("installation_key"), "inventory": registry.get("inventory")}):
                require(registry.get("operation") == journal["operation"], "update_installed_registry_mismatch")
            registry_matches(matched, observed)
        active_plugins = {row["plugin_id"]: row["version"] for row in observed["plugins"] if row["installed"]}
        plugin_target = next((target for target in targets if active_plugins == {
            key: value["version"] for key, value in target.get("plugins", {}).items()}), None)
        require(plugin_target is not None, "update_plugin_registry_mismatch")
        plugins_match(plugin_target, observed)
        pointers_match(self.runtime, candidate)
        # Validate the core and ledger while the plugin DB version still describes
        # the previous generation. The transaction publishes both together.
        runtime_target = dict(candidate, plugins={row["plugin_id"]: {"version": row["version"]}
                                                 for row in observed["plugins"] if row["installed"]})
        validate(runtime_target, observed, registry=False)
        registry_previous = matched if registry else plugin_target
        if observed.get("installed_release_available") is False:
            require(journal["status"] == "rolling_back" and inventory(candidate) == inventory(journal["previous"]),
                    "update_installed_registry_required")
        else:
            self.host.publish_installed(registry_previous, candidate, journal["operation"])
        observed = self.host.observe()
        validate(candidate, observed, self.runtime)
        atomic_json(self.installed_path, candidate)
        self.sync_notification_compose(journal, previous=candidate == journal["previous"])
        return observed

    def compose_publication_host(self, journal):
        if journal.get("candidate_acceptance"):
            files = acceptance_compose_order(journal, self.host.files)
            if [str(path) for path in self.host.files] == files:
                return self.host
            return DockerHost(files, self.host.health_url, self.host.ca_file,
                              self.host.timeout, self.host.tls_min_validity, self.host.drain_timeout)
        return self.host

    def settle_compose_switch(self, journal):
        switch = journal.get("notification_compose_switch")
        if not switch:
            return
        target = self.runtime / "state/install-compose.json"
        require(switch["path"] == str(target), "update_compose_changed")
        current = sha256(target)
        require(current in {switch["before"], switch["after"]}, "update_compose_changed")
        if switch.get("acknowledged"):
            require(current == switch["after"], "update_compose_changed")
            return
        if current == switch["after"]:
            # Admit only the exact hash from the durable publication intent if
            # a crash happened between atomic replacement and the journal ACK.
            require(self.compose_publication_host(journal).deployment_fingerprint() == switch["fingerprint"],
                    "update_configuration_changed")
            if str(target) in journal["compose_files"]:
                journal["compose_files"][str(target)] = current
            journal["deployment_fingerprint"] = switch["fingerprint"]
            switch["acknowledged"] = True

    def sync_notification_compose(self, journal, *, previous=False):
        target = self.runtime / "state/install-compose.json"
        if not target.exists():
            return  # Adopted installs can use an operator-owned Compose layout.
        source = Path(checked_override(journal, "previous_override" if previous else "candidate_override"))
        config = parse_json(source.read_bytes())
        current = parse_json(target.read_bytes())
        old_backup = config.get("services", {}).get("backup", {}).get("environment", {})
        live_backup = current.get("services", {}).get("backup", {}).get("environment", {})
        backup_changed = any((key in old_backup, old_backup.get(key)) != (
            key in live_backup, live_backup.get(key)) for key in DELTA_KEYS)
        if ("notification-delivery" not in config.get("services", {})
                and "notification-delivery" not in current.get("services", {}) and not backup_changed):
            return
        protected_path(target)
        require(str(target) in journal["compose_files"] and sha256(target) == journal["compose_files"][str(target)],
                "update_compose_changed")
        release = config
        config = complete_overlay(current, release)
        if previous:
            backup = config.get("services", {}).get("backup", {})
            environment = backup.get("environment", {})
            for key in DELTA_KEYS:
                if key in old_backup:
                    environment[key] = old_backup[key]
                else:
                    environment.pop(key, None)
        if previous and "notification-delivery" not in release.get("services", {}):
            # Rollback must remove the bounded addition without discarding storage.
            for name in ("notification-delivery", "notification-setup"):
                config["services"].pop(name, None)
            config.get("secrets", {}).pop("notification_db_password", None)
            api = config["services"].get("api", {})
            if "volumes" in api:
                api["volumes"] = [mount for mount in api["volumes"] if mount.get("target") != "/run/notification-setup"]
            migrate = config["services"].get("migrate", {})
            migrate.get("environment", {}).pop("SLI_NOTIFICATION_DB_PASSWORD_FILE", None)
            if "secrets" in migrate:
                migrate["secrets"] = [secret for secret in migrate["secrets"] if (
                    secret.get("source") if isinstance(secret, dict) else secret) != "notification_db_password"]
        replacement = Path(journal["directory"]) / ("notification-previous.json" if previous else "notification-candidate.json")
        atomic_json(replacement, config)
        host = self.compose_publication_host(journal)
        host.ownership_preflight(journal["previous"], host.configuration({str(target): replacement}))
        journal["notification_compose_switch"] = {"path": str(target), "before": sha256(target),
            "after": hashlib.sha256(canonical(config)).hexdigest(),
            "fingerprint": host.deployment_fingerprint(replacement={str(target): replacement})}
        self.save(journal)
        atomic_json(target, config)
        self.settle_compose_switch(journal)
        self.save(journal)

    def apply(self, package, *, operation_id=None):
        if operation_id is not None:
            require(re.fullmatch(r"[a-f0-9]{32}", operation_id), "update_invalid_operation")
            if self.journal_path.exists():
                active = self.read_journal(self.journal_path)
                if active["operation"] == operation_id or (self.state / "updates" / operation_id / "journal.json").exists():
                    return self.resume(operation_id=operation_id)
        with operation_lock(self.state):
            self.require_volume_reconciled()
            if self.reconciliation_path.exists():
                require(self.read_journal(self.reconciliation_path)["status"] == "committed",
                        "update_reconciliation_required")
            updates = self.state / "updates"
            updates.mkdir(mode=0o700, exist_ok=True)
            protected_path(updates, directory=True)
            updates.chmod(0o700)
            if self.journal_path.exists():
                journal = self.read_journal(self.journal_path)
                require(journal["status"] in {"committed", "rolled_back", "rejected"}, "update_resume_required")
                archived = self.state / "updates" / journal["operation"] / "journal.json"
                atomic_json(archived, parse_json(self.journal_path.read_bytes()))
            protected_path(self.installed_path)
            installed = parse_json(self.installed_path.read_bytes())
            # No Docker call, candidate load or configuration evaluation before signature checks.
            try:
                verified = self.verified(package, installed)
                manifest = verified.manifest
            except Exception as exc:
                operation = operation_id or uuid.uuid4().hex
                directory = self.state / "updates" / operation
                directory.mkdir(parents=True, mode=0o700)
                self.save({"format_version": 1, "operation": operation, "status": "rejected", "phase": "verify",
                           "completed": [], "reason": reason_code(exc, "update_verification_failed")})
                raise
            if manifest.get("component") == "plugin":
                from deploy.linux.plugin_update import apply
                return apply(self, verified, installed, operation_id)
            operation = operation_id or uuid.uuid4().hex
            directory = self.state / "updates" / operation
            directory.mkdir(parents=True, mode=0o700)
            copy = directory / "package.zip"
            with copy.open("xb") as stream:
                stream.write(verified.archive_bytes)
                stream.flush()
                os.fsync(stream.fileno())
            require(self.verify(copy, installed) == manifest, "update_package_changed")
            journal = {"format_version": 1, "operation": operation, "status": "running", "phase": "verify",
                       "completed": [], "previous": installed, "manifest": manifest,
                       "package_sha256": sha256(copy), "package": str(copy.resolve()),
                       "directory": str(directory.resolve()), "backup_id": None, "migration_started": False,
                       "checkpoint_key": os.urandom(32).hex(),
                       "candidate_tag": f"sli-update:candidate-{operation}", "reason": None,
                       "package_version": manifest["to_version"], "migration_ledger": None,
                       "desired_activation": {"version": manifest["to_version"], "image_tag": f"sli-update:candidate-{operation}",
                                              "image_digest": manifest["image"]["digest"]}, "observed_runtime": None,
                       "compose_files": {str(path): sha256(path) for path in self.host.files},
                       "services": [], "previous_override": str((directory / "previous.json").resolve()),
                       "candidate_override": str((directory / "candidate.json").resolve())}
            installation = str(self.state / "install-compose.json")
            if installation in journal["compose_files"]:
                journal["compose_snapshot"] = {"mode": "replace-installation-v1", "path": installation}
            self.save(journal)
            return self.run(journal)

    def resume(self, *, rollback=False, operation_id=None, allow_unhealthy_backup=False):
        with operation_lock(self.state):
            self.require_volume_reconciled()
            journal = self.operation(operation_id)
            if allow_unhealthy_backup:
                require(journal.get("component", "server") == "server" and journal.get("migration_started") is False,
                        "update_backup_waiver_not_allowed")
                require(rollback or journal["status"] in {"rolling_back", "recovery_required"},
                        "update_backup_waiver_not_allowed")
            require(not journal.get("candidate_acceptance") or journal["candidate_acceptance"].get("status") == "committed",
                    "update_candidate_acceptance_pending")
            if journal.get("component") == "plugin":
                from deploy.linux import plugin_update
                active = parse_json(self.journal_path.read_bytes())["operation"] == journal["operation"]
                if journal["status"] in {"rolled_back", "rejected"} or (journal["status"] == "committed" and not rollback):
                    if active:
                        (plugin_update.base(self, journal) / "draining.json").unlink(missing_ok=True)
                    return journal["status"]
                require(active, "update_operation_not_active")
                plugin_update.validate_resume(self, journal)
                if rollback or journal["status"] == "rolling_back" or (
                        journal["phase"] in {"drain", "activate", "health"} and journal["phase"] not in journal["completed"]):
                    return plugin_update.rollback(self, journal, "update_operator_rollback" if rollback else "update_interrupted_mutation")
                return plugin_update.run(self, journal)
            repair_stopped_previous = (rollback and operation_id is not None and journal["status"] == "rolled_back"
                and journal.get("reason") == "update_drain_service_timeout"
                and journal.get("migration_started") is False and not journal.get("recovery_started")
                and journal.get("backup_id") is None)
            if (journal["status"] in {"rolled_back", "rejected"} and not repair_stopped_previous) or (
                    journal["status"] == "committed" and not rollback):
                return journal["status"]
            active = self.read_journal(self.journal_path)
            # Explicitly repair the pre-migration late-stop race, including an
            # ensuing rejected apply. Never revive a superseded mutating update.
            require(active["operation"] == journal["operation"] or (repair_stopped_previous
                and active["status"] == "rejected" and active.get("completed") == []
                and active.get("migration_started") is False and active.get("previous") == journal["previous"]),
                "update_operation_not_active")
            uncertain = journal["phase"] in {"migrate", "activate", "health"} and journal["phase"] not in journal["completed"]
            recovering = journal["status"] in {"rolling_back", "recovery_required"}
            self.validate_resume(journal, rollback=rollback or recovering or uncertain)
            if rollback or recovering:
                return self.rollback(journal, "update_operator_rollback" if rollback else journal["reason"],
                                     **({"allow_unhealthy_backup": True} if allow_unhealthy_backup else {}))
            # A migration might have committed SQL without recording success. Never guess.
            if uncertain:
                return self.rollback(journal, "update_interrupted_mutation")
            return self.run(journal)

    def validate_resume(self, journal, *, rollback=False, acceptance=False):
        if journal.get("component") == "plugin":
            from deploy.linux.plugin_update import validate_resume
            return validate_resume(self, journal)
        require(journal["format_version"] == 1 and journal["phase"] in PHASES, "update_invalid_journal")
        require(journal["completed"] == list(PHASES[:len(journal["completed"])]), "update_invalid_journal")
        self.settle_compose_switch(journal)
        if not acceptance:
            require({str(path): sha256(path) for path in self.host.files} == journal["compose_files"], "update_compose_changed")
        protected_path(self.installed_path)
        installed = parse_json(self.installed_path.read_bytes())
        require(installed == journal["previous"] or (journal["phase"] == "commit" and installed == self.candidate(journal)),
                "update_installed_state_changed")
        if "verify" in journal["completed"]:
            require("compose_snapshot" not in journal or isinstance(journal.get("snapshot_fingerprints"), dict),
                    "update_configuration_changed")
            for key in (("previous_override",) if rollback else ("previous_override", "candidate_override")):
                checked_override(journal, key)
            if acceptance:
                self.host.acceptance_preflight(journal)
            else:
                require(self.host.deployment_fingerprint() == journal["deployment_fingerprint"], "update_configuration_changed")
                self.host.validate_operation_overrides(journal)
            if not rollback and journal["phase"] in {"stage", "checkpoint", "drain", "migrate"} and not journal["migration_started"]:
                self.previous_observation(journal)
        if not rollback:
            require(sha256(journal["package"]) == journal["package_sha256"], "update_package_changed")
            require(verify_package(journal["package"], self.trust_store, installed=journal["previous"], free_bytes=2**100).manifest
                    == journal["manifest"], "update_package_changed")
            if journal["phase"] in {"verify", "stage"} and "verify" in journal["completed"]:
                self.preflight(journal["previous"], journal["manifest"])

    def candidate(self, journal):
        result = dict(journal["previous"])
        result.update(version=journal["manifest"]["to_version"], image_tag=journal["candidate_tag"],
                      image_digest=journal["manifest"]["image"]["digest"], migrations=journal["manifest"]["migrations"],
                      override=journal["candidate_override"], source_commit=journal["manifest"]["source_commit"],
                      build_id=journal["manifest"]["build_id"], migration_ledger=journal["candidate_ledger"])
        result["ledger_source"] = "database"
        result["plugins"] = dict(result.get("plugins", {}))
        for plugin_id, value in bundled_core_plugins(
                journal["manifest"], applied_ledger=journal["previous"]["migration_ledger"]).items():
            result["plugins"].setdefault(plugin_id, value)
        return result

    def accept_candidate(self, *, operation_id, dry_run=False, allow_unhealthy_backup=False):
        """Explicit forward recovery; validation never invokes rollback or repair.

        Only this entry point may retry its durable decision. A failure after DB
        publication must not restore the checkpoint and discard newer data.
        """
        require(isinstance(operation_id, str) and re.fullmatch(r"[a-f0-9]{32}", operation_id),
                "update_invalid_operation")
        # Reading a damaged/missing key must not provision replacement authority.
        protected_path(self.state / "update-journal.key")
        with operation_lock(self.state):
            self.require_volume_reconciled()
            updater_journal = self.state / "updater-journal.json"
            if updater_journal.exists():
                protected_path(updater_journal)
                require(parse_json(_bounded_read(updater_journal, 64 * 1024)).get("status")
                        in {"committed", "rolled_back", "rejected", "failed"}, "update_updater_recovery_required")
            if self.reconciliation_path.exists():
                require(self.read_journal(self.reconciliation_path).get("status") == "committed",
                        "update_reconciliation_required")
            journal = self.read_journal(self.journal_path)
            require(journal.get("operation") == operation_id, "update_operation_not_active")
            decision = journal.get("candidate_acceptance")
            if journal.get("status") == "committed" and decision and decision.get("status") == "committed":
                if dry_run:
                    return "dry_run"
                # A prior replace may have succeeded before its directory fsync
                # failed. Explicit retry durably saves the same authenticated
                # decision without replaying any DB or runtime action.
                self.candidate_acceptance_started = True
                self.save(journal)
                return "committed"
            require(journal.get("status") == "recovery_required" and journal.get("component", "server") == "server"
                    and journal.get("manifest", {}).get("component") == "server"
                    and journal.get("completed") in [list(PHASES[:6]), list(PHASES[:7])]
                    and journal.get("phase") in {"health", "commit"}
                    and journal.get("migration_started") is True and journal.get("recovery_started") is True,
                    "update_candidate_acceptance_required")
            require(re.fullmatch(r"update-checkpoints/" + operation_id + r"/\d{8}T\d{6}\.\d{6}Z",
                                 journal.get("backup_id") or "")
                    and re.fullmatch(r"[a-f0-9]{64}", journal.get("checkpoint_sha256") or "")
                    and re.fullmatch(r"[a-f0-9]{64}", journal.get("checkpoint_key") or ""),
                    "update_checkpoint_required")
            require(decision is None or (decision.get("status") == "pending"
                    and decision.get("operation") == operation_id), "update_invalid_journal")
            require(sha256(journal["package"]) == journal["package_sha256"], "update_package_changed")
            require(self.verified(journal["package"], journal["previous"]).manifest == journal["manifest"],
                    "update_package_changed")
            self.validate_resume(journal, acceptance=True)
            candidate = self.candidate(journal)
            self.recovery_authority(journal, candidate)
            observed = self.host.runtime_matches(journal)
            from deploy.linux.installed_state import validate

            validate(candidate, observed, self.runtime, registry=False)
            if decision is not None:
                require(decision.get("candidate_sha256") == hashlib.sha256(canonical(candidate)).hexdigest(),
                        "update_installed_state_changed")
                accepted_files = dict(decision.get("compose_files", {}))
                switch = journal.get("notification_compose_switch") or {}
                if (switch.get("acknowledged") and accepted_files.get(switch.get("path")) == switch.get("before")):
                    accepted_files[switch["path"]] = switch["after"]
                require(accepted_files == {str(path): sha256(path) for path in self.host.files},
                        "update_compose_changed")
            health_evidence = (self.host.health(journal, backup_waiver="candidate") if allow_unhealthy_backup
                               else self.host.health(journal))
            # Health can wait minutes. Recheck identities/configuration before
            # recording intent; publish additionally rechecks ledger under SQL lock.
            self.host.acceptance_preflight(journal)
            observed = self.host.runtime_matches(journal)
            validate(candidate, observed, self.runtime, registry=False)
            self.recovery_authority(journal, candidate)
            if dry_run:
                return "dry_run"
            recovery_progress = ("rollback_restored", "rollback_runtime", "rollback_error",
                                 "rollback_fence_error", "recovery_api_unchecked", "backup_health_override")
            if decision is None:
                journal["candidate_acceptance"] = {
                    "operation": operation_id, "status": "pending", "action": "operator_accepted_candidate",
                    "actor_uid": os.geteuid() if hasattr(os, "geteuid") else None,
                    "requested_at_utc": datetime.now(timezone.utc).isoformat(),
                    "original_reason": journal.get("reason"), "rollback_error": journal.get("rollback_error"),
                    "rollback_runtime": journal.get("rollback_runtime"),
                    "candidate_sha256": hashlib.sha256(canonical(candidate)).hexdigest(),
                    "compose_files": {str(path): sha256(path) for path in self.host.files},
                    "source_compose_order": acceptance_compose_order(journal, self.host.files),
                }
            if allow_unhealthy_backup:
                audit = journal["candidate_acceptance"].setdefault("backup_health_override", {
                    "requested_at_utc": datetime.now(timezone.utc).isoformat(),
                    "actor_uid": os.geteuid() if hasattr(os, "geteuid") else None,
                    "reason": "operator_allowed_unhealthy_backup",
                })
                audit.update(health_evidence, verified_at_utc=datetime.now(timezone.utc).isoformat())
                journal["candidate_acceptance"]["backup_health"] = health_evidence["backup_health"]
            # Candidate reactivation invalidates the old rollback attempt's
            # progress. Retain its facts in audit, not as executable evidence
            # that a later explicit rollback may skip checkpoint restoration.
            journal["candidate_acceptance"].setdefault("original_recovery", {
                key: journal[key] for key in recovery_progress if key in journal})
            for key in recovery_progress:
                journal.pop(key, None)
            journal["phase"] = "commit"
            journal["completed"] = list(PHASES[:7])
            self.candidate_acceptance_started = True
            self.save(journal)  # Durable authenticated authorization before publication.
            # Never call run(): its exception handler restores the old checkpoint.
            journal["observed_runtime"] = self.publish(journal, candidate)
            journal["migration_ledger"] = {"max_version": journal["observed_runtime"]["migration_ledger_max"]}
            journal["desired_activation"] = {key: candidate[key] for key in ("version", "image_tag", "image_digest")}
            journal["candidate_acceptance"].update(status="committed", completed_at_utc=datetime.now(timezone.utc).isoformat())
            journal.update(status="committed", reason="operator_accepted_candidate", completed=list(PHASES))
            self.save(journal)
            return "committed"

    def previous_observation(self, journal):
        from deploy.linux.installed_state import ledger_matches, plugins_match, pointers_match, registry_matches, validate
        observed = self.host.observe()
        previous = journal["previous"]
        ledger_matches(previous, observed)
        registry_matches(previous, observed)
        plugins_match(previous, observed)
        pointers_match(self.runtime, previous)
        if observed["services"]:
            require(set(journal["services"]) <= set(observed["services"]), "update_running_version_mismatch")
            validate(previous, observed, self.runtime)
        return observed

    def recovery_authority(self, journal, candidate):
        """A recovery may repair this operation, never overwrite foreign state."""
        from deploy.linux.installed_state import inventory, installation_key, pointers_match
        observed = self.host.observe()
        previous = journal["previous"]
        registry = observed.get("installed_release")
        if registry:
            require(registry.get("installation_key") == installation_key(previous), "update_foreign_installation")
            require(registry.get("inventory") == inventory(previous) or (
                registry.get("inventory") == inventory(candidate) and registry.get("operation") == journal["operation"]),
                "update_installed_registry_mismatch")
        allowed = {row["version"]: row for row in candidate["migration_ledger"]}
        actual = observed.get("migration_ledger", [])
        require(actual and all(type(row.get("version")) is int for row in actual), "update_migration_ledger_mismatch")
        versions = [row["version"] for row in actual]
        require(versions == sorted(set(versions)) and type(observed.get("migration_ledger_max")) is int
                and observed["migration_ledger_max"] == max(versions)
                and {row["version"] for row in previous["migration_ledger"]} <= set(versions),
                "update_migration_ledger_mismatch")
        for row in actual:
            expected = allowed.get(row["version"])
            require(expected and row.get("name") == expected["name"] and (row.get("sha256") == expected["sha256"]
                or (row.get("sha256") is None and (journal.get("migration_started")
                    or (previous.get("ledger_source") == "deployed_image" and previous.get("adoption")
                        and observed.get("installed_release_available") is False)))), "update_migration_ledger_mismatch")
        plugin_versions = {key: {value["version"]} for key, value in previous.get("plugins", {}).items()}
        for key, value in candidate.get("plugins", {}).items():
            plugin_versions.setdefault(key, set()).add(value["version"])
        active = [row for row in observed["plugins"] if row["installed"]]
        active_ids = {row["plugin_id"] for row in active}
        previous_ids = set(previous.get("plugins", {}))
        require(len(active_ids) == len(active) and previous_ids <= active_ids <= set(plugin_versions)
                and (journal.get("migration_started") or active_ids == previous_ids) and all(
            row["version"] in plugin_versions[row["plugin_id"]] for row in active), "update_plugin_registry_mismatch")
        if journal.get("component") == "plugin":
            try:
                pointers_match(self.runtime, previous)
            except Exception:
                pointers_match(self.runtime, candidate)
        else:
            pointers_match(self.runtime, previous)

    def status(self, operation_id=None):
        from deploy.linux.installed_state import inventory, observe_plugins, validate
        with operation_lock(self.state):
            installed = parse_json(self.installed_path.read_bytes())
            if not self.journal_path.exists() and operation_id is None:
                journal = {"operation": None, "status": "idle", "phase": None,
                           "desired_activation": {key: installed[key] for key in ("version", "image_tag", "image_digest")}}
            else:
                journal = self.operation(operation_id)
            observed = self.host.observe()
            readiness = {"ready": True, "reason_code": None}
            try:
                validate(installed, observed, self.runtime)
                if observed.get("installed_release_available") is False:
                    readiness = {"ready": False, "reason_code": "update_ledger_attestation_required"}
            except Exception as exc:
                readiness = {"ready": False, "reason_code": reason_code(exc, "update_inventory_readback_failed")}
            services = list(observed["services"].values())
            active = None
            if services and all(row == services[0] for row in services):
                active = dict(services[0])
                registry = observed.get("installed_release")
                source = registry["inventory"] if registry else inventory(installed)
                if source["image_digest"] == active["image_digest"]:
                    active.update(build_id=source.get("build_id"), source_commit=source.get("source_commit"))
            return {"operation": journal["operation"], "status": journal["status"], "phase": journal["phase"],
                    "package_version": journal.get("package_version"),
                    "migration_ledger": {"max_version": observed["migration_ledger_max"]},
                    "desired_activation": journal.get("desired_activation"), "observed_runtime": observed,
                    "active_build": active, "active_plugins": observe_plugins(self.runtime, observed), "readiness": readiness,
                    "installed_inventory": inventory(installed),
                    "exact_migration_ledger": observed.get("migration_ledger"),
                    "tag_command": journal.get("tag_command"), **self.operation_result(journal)}

    def step(self, journal, phase):
        directory = Path(journal["directory"])
        if phase in {"checkpoint", "drain", "migrate", "activate"}:
            checked_override(journal, "candidate_override" if phase in {"migrate", "activate"} else "previous_override")
        if phase == "verify":
            self.host.validate_snapshot_binding(journal)
            self.host.ensure_secrets(journal["previous"])
            observed = self.preflight(journal["previous"], journal["manifest"])
            journal["observed_runtime"] = observed
            journal["migration_ledger"] = {"max_version": observed["migration_ledger_max"]}
            journal["services"] = sorted(observed["services"])
            journal["deployment_fingerprint"] = self.host.deployment_fingerprint()
            verified = verify_package(journal["package"], self.trust_store, installed=journal["previous"], free_bytes=2**100)
            require(verified.manifest == journal["manifest"], "update_package_changed")
            payload = directory / "payload"
            extract_payload(verified, payload)
            delta = load_deltas(payload, journal["manifest"])
            # Persist the complete previous runtime override, including prior deltas.
            previous = {"services": {name: {"image": journal["previous"]["image_tag"]}
                                     for name in [*journal["services"], "migrate"]}}
            installation = self.state / "install-compose.json"
            retained = {}
            if str(installation) in journal["compose_files"]:
                protected_path(installation)
                require(sha256(installation) == journal["compose_files"][str(installation)], "update_compose_changed")
                retained = parse_json(installation.read_bytes())
                previous = complete_overlay(retained, previous)
            if journal["previous"].get("override"):
                protected_path(journal["previous"]["override"])
                prior = parse_json(Path(journal["previous"]["override"]).read_bytes())
                if not retained or "volumes" not in prior:
                    # Legacy partial candidates carry bounded release additions.
                    # A complete retained installation is authoritative: never replay
                    # its stale operator snapshot from an earlier candidate.
                    for name, value in prior["services"].items():
                        if name == "backup" and name in previous["services"]:
                            for key, setting in value.get("environment", {}).items():
                                if key in DELTA_KEYS:
                                    previous["services"][name].setdefault("environment", {}).setdefault(key, setting)
                        if name in {"notification-delivery", "notification-setup"} and name in previous["services"]:
                            if name not in retained.get("services", {}):
                                previous["services"][name] = value
                        if name in {"api", "migrate"} and name in previous["services"]:
                            for key in ("volumes", "secrets"):
                                if key in value:
                                    managed = [item for item in value[key] if (
                                        item.get("target") == "/run/notification-setup" if key == "volumes" else (
                                            item.get("source") if isinstance(item, dict) else item) == "notification_db_password")]
                                    if managed:
                                        previous = complete_overlay(previous, {"services": {name: {key: managed}}})
                    secret = prior.get("secrets", {}).get("notification_db_password")
                    if secret is not None:
                        previous.setdefault("secrets", {}).setdefault("notification_db_password", secret)
                if "volumes" in prior:
                    previous = complete_overlay(previous, {"volumes": prior["volumes"]})
            candidate = json.loads(json.dumps(previous))
            for name in [*journal["services"], "migrate"]:
                candidate["services"][name]["image"] = journal["candidate_tag"]
            if any(Path(path).name == "261_telegram_delivery.sql" for path in journal["manifest"]["migrations"]):
                from deploy.linux.sli_secrets import _directory, ensure

                config = parse_json(self.host.compose(["config", "--format", "json"]))
                secret_directory = Path(config["secrets"]["runtime_password"]["file"]).parent
                ensure(secret_directory, names=["notification_db_password"])
                _directory(secret_directory / "notifications")
                _directory(secret_directory / "notification-control")
                add_notification_services(candidate, image=journal["candidate_tag"],
                                          secret_directory=secret_directory, public_url=self.host.health_url)
                journal["added_services"] = sorted({"notification-setup", "notification-delivery"} - set(journal["services"]))
            if delta:
                candidate["services"]["backup"].setdefault("environment", {}).update(delta)
            atomic_json(Path(journal["previous_override"]), previous)
            atomic_json(Path(journal["candidate_override"]), candidate)
            for key in ("previous_override", "candidate_override"):
                journal[key + "_sha256"] = sha256(journal[key])
            fingerprints = self.host.validate_operation_overrides(journal)
            if journal.get("compose_snapshot") is not None:
                journal["snapshot_fingerprints"] = fingerprints
            with tempfile.TemporaryDirectory(dir=directory) as temporary:
                additions = image_inventory(payload / journal["manifest"]["image"]["path"], journal["manifest"],
                                            Path(temporary) / "image.tar", applied_ledger=journal["previous"]["migration_ledger"])
            ledger = {row["version"]: row for row in journal["previous"]["migration_ledger"]}
            for row in additions:
                require(row["version"] not in ledger or ledger[row["version"]] == row, "update_migration_ledger_mismatch")
                ledger[row["version"]] = row
            journal["candidate_ledger"] = [ledger[key] for key in sorted(ledger)]
            from deploy.linux.installed_state import ledger_matches
            ledger_matches({"migrations": journal["manifest"]["migrations"], "migration_ledger": journal["candidate_ledger"]},
                           {"migration_ledger": journal["candidate_ledger"], "migration_ledger_max": max(ledger)})
        elif phase == "stage":
            self.host.stage(directory / "payload", journal["manifest"], journal["candidate_tag"])
            # Read only nightly evidence while the previous release serves requests.
            self.host.check_backup(journal)
        elif phase == "drain":
            self.host.drain(journal)
        elif phase == "checkpoint":
            self.previous_observation(journal)
            # Fence writers before activation; the following drain phase
            # rechecks the fence before migration, including after interruption.
            self.host.drain(journal)
            checkpoint = self.host.checkpoint(journal)
            require(re.fullmatch(r"update-checkpoints/" + journal["operation"] + r"/\d{8}T\d{6}\.\d{6}Z", checkpoint["backup_id"])
                    and re.fullmatch(r"[a-f0-9]{64}", checkpoint["checkpoint_sha256"]), "update_invalid_checkpoint")
            journal["backup_id"] = checkpoint["backup_id"]
            journal["checkpoint_sha256"] = checkpoint["checkpoint_sha256"]
            if checkpoint.get("daily_backup"):
                journal["daily_backup"] = checkpoint["daily_backup"]
        elif phase == "migrate":
            self.previous_observation(journal)
            require(journal["backup_id"], "update_checkpoint_required")
            if journal["manifest"].get("recovery_profile", "full") in {"ui-only", "history", "files"}:
                return
            journal["migration_started"] = True
            self.save(journal)
            # Migrator also enforces its canonical ledger; inventory was verified offline.
            self.host.migrate(journal)
        elif phase == "activate":
            journal["recovery_started"] = True
            self.save(journal)
            self.host.activate(journal)
        elif phase == "health":
            self.host.health(journal)
        elif phase == "commit":
            self.host.health(journal)
            journal["observed_runtime"] = self.host.runtime_matches(journal)
            journal["migration_ledger"] = {"max_version": journal["observed_runtime"]["migration_ledger_max"]}
            journal["tag_command"] = f"git tag -a sli-{journal['manifest']['to_version']} {journal['manifest']['source_commit']}"
            journal["observed_runtime"] = self.publish(journal, self.candidate(journal))

    def run(self, journal):
        try:
            for phase in PHASES:
                if phase in journal["completed"]:
                    continue
                journal["phase"] = phase
                self.save(journal)  # Intent must be durable before the external side effect.
                self.step(journal, phase)
                journal["completed"].append(phase)
                self.save(journal)
            journal["status"] = "committed"
            self.save(journal)
            return "committed"
        except Exception as exc:
            reason = reason_code(exc, "update_phase_failed")
            if journal["phase"] == "verify" or (not journal.get("drain_services")
                    and not journal["migration_started"] and (reason == "update_backup_busy" or (
                        journal["phase"] in {"stage", "checkpoint"} and reason in {
                            "update_daily_backup_schema_mismatch", "update_fresh_daily_backup_required"}))):
                journal.update(status="rejected", reason=reason,
                               desired_activation={key: journal["previous"][key] for key in ("version", "image_tag", "image_digest")})
                self.save(journal)
                return "rejected"
            if reason.endswith("mismatch") and not journal["migration_started"] and not journal.get("recovery_started"):
                journal["reason"] = reason
                self.save(journal)
                raise UpdateError(reason) from None
            return self.rollback(journal, reason)

    def rollback(self, journal, reason, *, allow_unhealthy_backup=False):
        if allow_unhealthy_backup:
            require(journal.get("component", "server") == "server" and journal.get("migration_started") is False,
                    "update_backup_waiver_not_allowed")
            journal["backup_health_override"] = {
                "status": "requested", "action": "rollback", "operation": journal["operation"],
                "actor_uid": os.geteuid() if hasattr(os, "geteuid") else None,
                "requested_at_utc": datetime.now(timezone.utc).isoformat(),
                "reason": "operator_allowed_unhealthy_backup", "original_reason": reason,
            }
        journal["status"], journal["reason"] = "rolling_back", reason
        journal["rollback_runtime"] = "unverified"
        journal.pop("rollback_error", None)
        journal.pop("rollback_fence_error", None)
        journal["desired_activation"] = {key: journal["previous"][key] for key in ("version", "image_tag", "image_digest")}
        self.save(journal)
        owned = False
        try:
            if "stage" in journal["completed"]:
                self.recovery_authority(journal, self.candidate(journal))
                checked_override(journal, "previous_override")
                # Before any data mutation, a pending soft stop is safe to wait
                # for, but not safe to race with activation or force containment.
                owned = bool(journal["migration_started"] or journal.get("recovery_started"))
                if hasattr(self.host, "settle_stops"):
                    self.host.settle_stops(journal)
                owned = True
                self.host.stop_operation(journal)
                # Before mutation the old version still owns all durable work.
                # Repeating a failed lease drain would also prevent its restart.
                if journal["migration_started"] or journal.get("recovery_started"):
                    self.host.drain(journal)
                restore_required = journal["migration_started"] or (
                    journal.get("recovery_started") and journal["manifest"].get("recovery_profile") in {"history", "files"})
                if restore_required and not journal.get("rollback_restored"):
                    require(journal["backup_id"], "update_checkpoint_required")
                    self.host.restore(journal)
                    journal["rollback_restored"] = True
                    self.save(journal)
                # Publish the authenticated previous managed settings before Compose
                # activation: an absent environment key cannot mask a candidate key
                # still present in the installation file underneath the override.
                self.sync_notification_compose(journal, previous=True)
                self.host.activate(journal, previous=True)
                journal["observed_runtime"] = self.host.runtime_matches(journal, previous=True)
                journal["migration_ledger"] = {"max_version": journal["observed_runtime"]["migration_ledger_max"]}
                journal["observed_runtime"] = self.publish(journal, journal["previous"], previous=self.candidate(journal))
                # Version/ledger recovery and availability are separate facts. If
                # an old worker is unhealthy, retain the coherent previous release
                # and report recovery_required instead of an endless rolling_back.
                journal["rollback_runtime"] = "previous"
                self.save(journal)
                if allow_unhealthy_backup:
                    require(journal.get("migration_started") is False, "update_backup_waiver_not_allowed")
                    evidence = self.host.health(journal, backup_waiver="previous")
                    journal["backup_health_override"].update(evidence, status="verified",
                        verified_at_utc=datetime.now(timezone.utc).isoformat())
                    self.save(journal)
                else:
                    self.host.health(journal)
            journal["status"] = "rolled_back"
            journal.pop("rollback_error", None)
            journal.pop("rollback_fence_error", None)
            self.save(journal)
            return "rolled_back"
        except Exception as exc:
            journal["rollback_error"] = reason_code(exc, "update_rollback_failed")
            if owned and journal["rollback_runtime"] != "previous":
                try:
                    self.host.fence(journal)
                    journal["rollback_runtime"] = "stopped"
                except Exception as fence_exc:
                    journal["rollback_fence_error"] = reason_code(fence_exc, "update_rollback_fence_failed")
            # Preserve the authenticated intent/checkpoint, but make this attempt
            # terminal. Only resume/recover may retry; a new apply stays blocked.
            journal["status"] = "recovery_required"
            self.save(journal)
            return "recovery_required"

    def operation_result(self, journal):
        result = {"status": journal["status"], "operation": journal["operation"],
                  "source_commit": journal.get("manifest", {}).get("source_commit"),
                  "reason_code": journal.get("reason")}
        audit = (journal.get("candidate_acceptance") or {}).get("backup_health_override") if journal["status"] == "committed" else journal.get("backup_health_override")
        if audit and audit.get("backup_health") == "operator_waived":
            result["backup_health"] = "operator_waived"
        result.update(drain_failure_diagnostic(journal))
        if journal.get("daily_backup"):
            result["daily_backup"] = journal["daily_backup"]
        if journal["status"] == "recovery_required":
            result.update(reason_code="update_rollback_failed", update_reason_code=journal.get("reason"),
                          rollback_reason_code=journal.get("rollback_error"),
                          rollback_runtime=journal.get("rollback_runtime", "unverified"))
            if journal.get("rollback_fence_error"):
                result["rollback_fence_reason_code"] = journal["rollback_fence_error"]
        return result


def apply_update(
    package: Path, *, trust_store: Path | None = None, dry_run: bool = False,
    restart_mode: str = "auto", skip_tests: bool = False, runtime: Path | None = None,
    host=None, operation_id=None,
):
    """Verify-only for v1; v2 activation always uses the journaled lifecycle."""
    require_complete_updater()
    result = {"status": "rejected", "installed": False, "executed": False}
    if trust_store is None:
        return {**result, "reason_code": "external_trust_required"}
    if not dry_run and operation_id is not None and runtime is not None and host is not None and restart_mode == "auto":
        require(re.fullmatch(r"[a-f0-9]{32}", operation_id), "update_invalid_operation")
        updater = Updater(runtime, trust_store, host)
        if updater.journal_path.exists():
            active = updater.read_journal(updater.journal_path)
            if active["operation"] == operation_id or (updater.state / "updates" / operation_id / "journal.json").exists():
                journal = updater.operation(operation_id)
                executed = journal["status"] not in {"committed", "rolled_back", "rejected"}
                status = updater.resume(operation_id=operation_id)
                journal = updater.operation(operation_id)
                return {**result, **updater.operation_result(journal), "installed": status == "committed",
                        "executed": executed,
                        "tag_command": journal.get("tag_command") if status == "committed" else None}
    try:
        verified = verify_package(package, trust_store)
    except (UpdateError, OSError):
        return {**result, "reason_code": "package_verification_failed"}
    result.update(verified.summary())
    if verified.manifest["schema_version"] == 1:
        if dry_run:
            return result
        return {**result, "status": "blocked", "reason_code": "runtime_schema_unsupported"}
    if runtime is None or host is None or restart_mode != "auto":
        return {**result, "status": "blocked", "reason_code": "runtime_configuration_required"}
    updater = Updater(runtime, trust_store, host)
    if dry_run:
        with operation_lock(updater.state):
            protected_path(updater.installed_path)
            installed = parse_json(updater.installed_path.read_bytes())
            verified = updater.verified(package, installed)
            with tempfile.TemporaryDirectory(dir=updater.state) as temporary:
                directory = Path(temporary)
                payload = directory / "payload"
                extract_payload(verified, payload)
                if verified.manifest.get("component") == "plugin":
                    from deploy.linux.plugin_update import validate_payload
                    validate_payload(payload, verified.manifest)
                else:
                    load_deltas(payload, verified.manifest)
                    image_inventory(payload / verified.manifest["image"]["path"], verified.manifest, directory / "image.tar")
            if verified.manifest.get("component") == "plugin":
                host.plugin_preflight(runtime, installed, verified.manifest)
            else:
                updater.preflight(installed, verified.manifest)
        return result
    status = updater.apply(package, operation_id=operation_id)
    journal = updater.operation(operation_id)
    return {**result, **updater.operation_result(journal), "installed": status == "committed", "executed": True,
            "tag_command": journal.get("tag_command") if status == "committed" else None}


def rollback_update(backup=None, *, dry_run=False, runtime=None, trust_store=None, host=None, operation_id=None,
                    allow_unhealthy_backup=False):
    """Recovery accepts the host journal and its checkpoint, never a source ZIP."""
    require_complete_updater()
    result = {"status": "blocked", "installed": False, "executed": False}
    if backup is not None:
        return {**result, "reason_code": "journal_recovery_required"}
    if runtime is None or host is None or trust_store is None:
        return {**result, "reason_code": "runtime_configuration_required"}
    updater = Updater(runtime, trust_store, host)
    if dry_run:
        with operation_lock(updater.state):
            journal = updater.operation(operation_id)
            if allow_unhealthy_backup:
                require(journal.get("component", "server") == "server" and journal.get("migration_started") is False,
                        "update_backup_waiver_not_allowed")
            updater.validate_resume(journal, rollback=True)
        return {**result, "status": "dry_run"}
    status = updater.resume(rollback=True, operation_id=operation_id,
                            **({"allow_unhealthy_backup": True} if allow_unhealthy_backup else {}))
    return {**result, **updater.operation_result(updater.operation(operation_id)),
            "installed": False, "executed": status in {"rolled_back", "recovery_required"}}


def capacity_service_unit(command, *, user, working_directory=None):
    """Render only; the operator installs/enables this on the existing host."""
    require(re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user), "update_capacity_service_invalid")
    require(command and all(isinstance(arg, str) and arg and not any(c in arg for c in "\r\n\x00")
                            for arg in command), "update_capacity_service_invalid")
    def quote(arg):
        return '"' + arg.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%').replace('$', '$$') + '"'
    directory = working_directory or str(Path(command[1]).parent)
    require(isinstance(directory, str) and directory.startswith("/") and not any(c in directory for c in "\r\n\x00"),
            "update_capacity_service_invalid")
    return ("[Unit]\nDescription=SLI PostgreSQL restore capacity witness\nAfter=docker.service\n"
            "StartLimitIntervalSec=0\n\n[Service]\nType=simple\nUser=" + user + "\n"
            "WorkingDirectory=" + quote(directory) + "\nExecStart=" + " ".join(map(quote, command)) + "\nRestart=always\nRestartSec=10\n"
            "KillSignal=SIGTERM\nTimeoutStopSec=35\nNoNewPrivileges=yes\nUMask=0077\n"
            "\n[Install]\nWantedBy=multi-user.target\n")


def watch_pg_capacity(host, runtime, *, stop=None):
    import signal
    import threading

    stop = stop or threading.Event()
    previous = {}
    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous[signum] = signal.signal(signum, lambda *_: stop.set())
        # Distinct lock: witness must remain alive while updater waits for backup.
        with operation_lock(Path(runtime) / "state/capacity"):
            while not stop.is_set():
                try:
                    host.publish_pg_capacity()
                    print("update_capacity_published", flush=True)
                except Exception:  # noqa: BLE001 - emit only fixed codes, never host errors
                    # A failed probe NEVER refreshes an earlier successful receipt.
                    # Its 30-second expiry closes admission; supervisor remains alive.
                    print("update_capacity_unavailable", flush=True)
                stop.wait(10)
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    return {"status": "stopped"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["verify", "apply", "resume", "rollback", "selftest", "status", "recover", "adopt", "reconcile", "reconcile-volumes", "capacity-watch", "capacity-service"])
    parser.add_argument("--capacity-user", help="Existing Linux updater operator; no new group or privilege grants.")
    parser.add_argument("--launcher", type=Path, help="Existing operator-provisioned trusted updater launcher.")
    parser.add_argument("--operation-id", help="Durable 32-character lowercase hex operation ID.")
    parser.add_argument("--component", choices=["server", "updater"], default="server")
    parser.add_argument("--expected-version", help="Expected updater release for offline selftest.")
    recovery = parser.add_mutually_exclusive_group()
    recovery.add_argument("--rollback-server", action="store_true", help="Восстановить сервер из checkpoint журнала.")
    recovery.add_argument("--rollback-updater", action="store_true", help="Вернуть указатель прежнего средства обновления.")
    recovery.add_argument("--accept-candidate", action="store_true",
                          help="Принять уже работающий проверенный кандидат без восстановления checkpoint.")
    parser.add_argument("--package", type=Path)
    parser.add_argument("--backup", type=Path, help="Legacy source backups are rejected.")
    parser.add_argument("--runtime", type=Path, default=Path("C:/SLI") if os.name == "nt" else Path("/srv/sli"))
    parser.add_argument("--trust-store", type=Path, help="Externally provisioned JSON trust policy (required).")
    parser.add_argument("--compose", type=Path, action="append")
    parser.add_argument("--health-url", default="https://127.0.0.1:8443/api/health/ready")
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--health-timeout", type=int, default=300)
    parser.add_argument("--drain-timeout", type=int, default=300,
                        help="Total seconds to finish admitted requests, worker batches and live leases (default: 300).")
    parser.add_argument("--tls-min-validity-seconds", type=int, default=86400)
    parser.add_argument("--restart", choices=["auto", "always", "never"], default="auto")
    parser.add_argument("--skip-tests", action="store_true", help="Cannot bypass package verification.")
    parser.add_argument("--allow-unhealthy-backup", action="store_true",
                        help="Явно разрешить только unhealthy/starting backup при recovery; не отменяет image/TLS проверки.")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        require(args.health_timeout > 0)
        if UPDATER_RELEASE_VERSION == "1.0.1":
            allowed = (args.action == "selftest"
                       or args.action in {"verify", "apply"} and args.component == "updater"
                       or args.action == "recover" and not args.rollback_server
                       or args.action == "status" and not (args.compose or args.operation_id))
            require(allowed, "update_updater_transition_required")
        if args.allow_unhealthy_backup:
            require(not (args.action == "resume" and args.dry_run), "update_backup_waiver_dry_run_unsupported")
            require(args.component == "server" and (args.action in {"resume", "rollback"}
                    or (args.action == "recover" and args.accept_candidate)), "update_backup_waiver_not_allowed")
            require(args.compose and args.ca_file and args.trust_store and args.operation_id,
                    "update_runtime_configuration_required")
        if args.accept_candidate:
            from server.sli.release_package import UPDATER_RELEASE_VERSION as recovery_updater_version

            require(recovery_updater_version != "1.0.1", "update_updater_transition_required")
            require(args.action == "recover" and args.component == "server" and args.operation_id is not None
                    and args.compose and args.ca_file and args.trust_store, "update_runtime_configuration_required")
        # These entry points do not even construct a Docker/API/DB adapter.
        if args.action == "capacity-service":
            require(sys.platform == "linux" and args.compose and args.launcher and args.capacity_user,
                    "update_runtime_configuration_required")
            import pwd

            require(args.capacity_user == pwd.getpwuid(os.geteuid()).pw_name, "update_capacity_operator_mismatch")
            protected_path(args.launcher)
            command = [sys.executable, "-I", "-B", str(args.launcher.resolve()), "--runtime", str(args.runtime.resolve()),
                       "capacity-watch"]
            for path in args.compose:
                command.extend(["--compose", str(path.resolve())])
            print(capacity_service_unit(command, user=args.capacity_user, working_directory=str(args.runtime.resolve())), end="")
            return 0
        elif args.action == "capacity-watch":
            require(sys.platform == "linux" and args.compose and not args.dry_run, "update_runtime_configuration_required")
            host = DockerHost(args.compose, args.health_url, args.ca_file)
            return 0 if watch_pg_capacity(host, args.runtime)["status"] == "stopped" else 1
        elif args.action == "selftest":
            from deploy.linux.updater_component import selftest
            result = {"status": selftest(args.expected_version)}
        elif args.action == "recover" or (args.action == "status" and not (args.compose or args.operation_id)):
            from deploy.linux.update_recovery import console_status, print_status, recover_server
            result = console_status(args.runtime)
            if not args.json:
                print_status(result)
            if args.action == "recover" and args.accept_candidate:
                from deploy.linux.update_recovery import accept_candidate

                host = DockerHost(args.compose, args.health_url, args.ca_file, args.health_timeout,
                                  args.tls_min_validity_seconds, drain_timeout=args.drain_timeout)
                result = accept_candidate(args.runtime, args.trust_store, host, args.operation_id, dry_run=args.dry_run,
                    **({"allow_unhealthy_backup": True} if getattr(args, "allow_unhealthy_backup", False) else {}))
                if not args.json:
                    if result["status"] == "recovery_required":
                        if result.get("durability") == "unverified":
                            print("Долговечность записи не подтверждена; состояние требует проверки.")
                        print("Принятие не завершено; часть состояния могла быть записана. "
                              "Повторите recover --accept-candidate с тем же --operation-id. Не запускайте откат.")
                    else:
                        print("Проверки пройдены; состояние не изменено." if args.dry_run else
                              "Работающая версия принята. Контрольная копия и журнал сохранены.")
            elif args.action == "recover" and not args.dry_run:
                if args.rollback_updater:
                    from deploy.linux.updater_component import UpdaterComponent
                    result = {"status": UpdaterComponent(args.runtime).rollback()}
                    if not args.json:
                        print("Указатель средства обновления возвращён к прежней версии.")
                elif args.rollback_server:
                    require(args.compose, "update_runtime_configuration_required")
                    host = DockerHost(args.compose, args.health_url, args.ca_file, args.health_timeout,
                                      args.tls_min_validity_seconds, drain_timeout=args.drain_timeout)
                    if not args.json:
                        print("Восстановление прежней версии из checkpoint. Записи после checkpoint будут потеряны.")
                    result = recover_server(args.runtime, args.trust_store, host)
                    if not args.json and result["status"] == "rolled_back":
                        print("Прежняя версия восстановлена. Готовность API не проверена; "
                              "проверьте сервисы перед возвратом пользователей.")
                    elif not args.json and result["status"] == "recovery_required":
                        print("Восстановление не завершено. Сохраните checkpoint и журнал; "
                              "устраните причину и повторите recover --rollback-server.")
                        print_status(console_status(args.runtime))
                    elif not args.json:
                        print("Отклонённая операция не требует восстановления из checkpoint.")
                elif not args.json:
                    print("Для восстановления используйте --rollback-server или --rollback-updater.")
        elif args.action in {"verify", "apply"} and args.component == "updater":
            from deploy.linux.updater_component import UpdaterComponent
            require(args.package is not None, "update_package_required")
            status = UpdaterComponent(args.runtime, args.trust_store).apply(
                args.package, dry_run=args.action == "verify" or args.dry_run)
            result = {"status": status, "installed": status == "committed"}
        elif args.action == "reconcile-volumes":
            require(args.compose and args.operation_id is not None, "update_runtime_configuration_required")
            host = DockerHost(args.compose, args.health_url, args.ca_file, args.health_timeout,
                              args.tls_min_validity_seconds, drain_timeout=args.drain_timeout)
            status = Updater(args.runtime, args.trust_store or args.runtime / "unused-trust", host).reconcile_volumes(
                args.operation_id, dry_run=args.dry_run)
            result = {"status": status, "installed": False, "executed": False}
        elif args.action == "reconcile":
            require(args.package is not None and args.trust_store is not None and args.compose and args.ca_file,
                    "update_runtime_configuration_required")
            host = DockerHost(args.compose, args.health_url, args.ca_file, args.health_timeout,
                              args.tls_min_validity_seconds, drain_timeout=args.drain_timeout)
            status = Updater(args.runtime, args.trust_store, host).reconcile(args.package, dry_run=args.dry_run)
            result = {"status": status, "installed": False, "executed": False}
        elif args.action == "adopt":
            from deploy.linux.installation import InstallationHost, adopt
            try:
                require(args.compose, "adopt_compose_required")
                host = InstallationHost(args.compose, args.health_url, args.ca_file, args.health_timeout,
                                        args.tls_min_validity_seconds)
                result = adopt(args.runtime, host, dry_run=args.dry_run)
            except UpdateError as exc:
                code = str(exc)
                code = code if re.fullmatch(r"(?:adopt|update|installation)_[a-z0-9_]+", code) else "adopt_failed"
                result = {"status": "rejected", "reason_code": code, "installed": False, "executed": False}
        else:
            host = DockerHost(args.compose, args.health_url, args.ca_file, args.health_timeout,
                              args.tls_min_validity_seconds, drain_timeout=args.drain_timeout) if args.compose and args.ca_file else None
            result = runtime_action(args, host)
        if not args.json and result.get("backup_health") == "operator_waived":
            print("Проверка здоровья backup пропущена оператором; проверка восстановления не подтверждена.")
        if not args.json and drain_failure_message(result):
            print(drain_failure_message(result))
        if args.json or (args.action == "status" and (args.compose or args.operation_id)):
            print(json.dumps(result))
        elif args.action not in {"status", "recover"}:
            print("update_" + result["status"])
            if result.get("operation"):
                print("operation=" + result["operation"])
            if result.get("reason_code"):
                print(result["reason_code"])
            if result.get("tag_command"):
                print(result["tag_command"])
        return 0 if result["status"] in {"committed", "verified", "dry_run", "selftest_passed", "status", "adopted", "reconciled"} or (
            args.action in {"rollback", "recover"} and result["status"] == "rolled_back") or (
            args.action == "recover" and result["status"] == "rejected") or args.action == "status" else 1
    except Exception as exc:
        code = reason_code(exc, "update_failed")
        if args.json:
            print(json.dumps({"status": "failed", "reason_code": code, "installed": False, "executed": False}))
        elif args.action in {"recover", "status", "selftest"} or args.component == "updater":
            messages = {
                "update_package_verification_failed": "Пакет отклонён: не пройдена проверка подписи, содержимого или совместимости.",
                "update_updater_activation_failed": "Новая версия updater не активирована либо требует восстановления. Проверьте журнал и указатель.",
                "update_previous_updater_required": "Нет сохранённой предыдущей версии updater для отката.",
                "update_updater_files_changed": "Файлы сохранённого updater повреждены; переключение запрещено.",
                "update_current_updater_required": "Запустите самообновление через launcher текущей доверенной версии updater.",
                "update_external_trust_required": "Для самообновления укажите внешний --trust-store.",
                "update_runtime_configuration_required": "Для восстановления сервера укажите исходные --compose файлы установки.",
                "update_updater_recovery_required": "Сначала завершите восстановление updater командой recover --rollback-updater.",
                "update_resume_required": "Сначала завершите незакрытую операцию сервера через resume или recover --rollback-server.",
                "update_rollback_failed": "Восстановление не завершено. Сохраните checkpoint; устраните причину и повторите recover --rollback-server.",
                "update_candidate_acceptance_pending": "Принятие версии не завершено. Повторите recover --accept-candidate с тем же --operation-id. Автоматический откат запрещён.",
                "update_candidate_acceptance_required": "Принятие разрешено только для незавершённого восстановления после успешной миграции и активации.",
                "update_configuration_changed": "Компоновка отличается от проверенного кандидата. Сверьте compose-файлы; принятие отменено.",
                "update_runtime_mismatch": "Не все службы работают на точном образе и теге кандидата. Принятие отменено.",
                "update_migration_ledger_mismatch": "Журнал миграций не совпадает с кандидатом. Принятие отменено; данные не исправлялись.",
                "update_health_timeout": "Готовность API и обязательных служб не подтверждена. Принятие отменено.",
            }
            message = messages.get(str(exc)) if isinstance(exc, UpdateError) else None
            print(message or "Операция не завершена. Проверьте локальный журнал; сохраните checkpoint "
                  "и прежнюю версию средства обновления.", file=sys.stderr)
        else:
            print(code, file=sys.stderr)
        return 1


def runtime_action(args, host):
    if args.action in {"verify", "apply"}:
        require(args.package is not None, "update_package_required")
        result = apply_update(args.package, trust_store=args.trust_store,
                              dry_run=args.action == "verify" or args.dry_run,
                              runtime=args.runtime, host=host, restart_mode=args.restart, skip_tests=args.skip_tests,
                              operation_id=args.operation_id)
    elif args.action == "rollback":
        result = rollback_update(args.backup, dry_run=args.dry_run, runtime=args.runtime,
                                 trust_store=args.trust_store, host=host, operation_id=args.operation_id,
                                 **({"allow_unhealthy_backup": True} if getattr(args, "allow_unhealthy_backup", False) else {}))
    else:
        require(host is not None and args.trust_store is not None, "update_runtime_configuration_required")
        updater = Updater(args.runtime, args.trust_store, host)
        if args.action == "status":
            result = updater.status(args.operation_id)
        else:
            status = updater.resume(operation_id=args.operation_id,
                                    **({"allow_unhealthy_backup": True} if getattr(args, "allow_unhealthy_backup", False) else {}))
            journal = updater.operation(args.operation_id)
            result = {**updater.operation_result(journal),
                      "tag_command": journal.get("tag_command") if status == "committed" else None}
    return result


if __name__ == "__main__":
    raise SystemExit(main())

