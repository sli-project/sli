"""Bounded, read-only verification of SLI release packages.

The external trust store is provisioned by the operator, never by a package.
Verification grants no permission to execute, install, migrate or restart.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import os
import re
import stat
import struct
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any
from types import MappingProxyType

MANIFEST_NAME = "SLI_RELEASE.json"
SIGNATURE_NAME = "SLI_SIGNATURE.json"
SIGNING_CONTEXT = b"SLI-RELEASE-V1\x00"
UPDATER_VERSION = 1
UPDATER_RELEASE_VERSION = "1.1.0"
UPDATER_FILES = frozenset({
    "deploy/linux/sli_update.py", "deploy/linux/update_checkpoint.py",
    "deploy/linux/backup.py", "deploy/linux/restore_existing.py", "deploy/linux/backup_restore_check.py",
    "deploy/linux/updater_component.py", "deploy/linux/update_recovery.py",
    "deploy/linux/installation.py", "deploy/linux/adoption_probe.py",
    "deploy/linux/sli_secrets.py", "deploy/linux/secrets-manifest.json",
    "server/sli/agents/ca.py",
    "server/sli/core/notification_secrets.py", "server/sli/core/secret_files.py",
    "server/sli/core/ad_credential_secrets.py",
    "scripts/maintenance/release_package.py",
    "server/sli/release_package.py",
})
# Fixed proposed release contracts. Signature verification does not authorize
# activation; the component separately enforces the operator launcher gate.
UPDATER_CLOSURE_FILES = UPDATER_FILES | frozenset({
    "deploy/linux/installed_state.py", "deploy/linux/plugin_update.py",
    "deploy/linux/backup_activity.py", "server/sli/plugin_validation.py",
    "config/plugin_architecture_v3.json",
})
UPDATER_TRANSITION_RELEASES = MappingProxyType({
    "1.0.1": ("1.0.0", "legacy-17"),
    "1.1.0": ("1.0.1", "closure-22"),
})
MIGRATION_MARKER = re.compile(
    r"insert\s+into\s+(?:public\.)?schema_migrations\s*"
    r"\(\s*version\s*,\s*name\s*\)\s*values\s*"
    r"\(\s*(\d+)\s*,\s*'([^']+)'",
    re.IGNORECASE | re.DOTALL,
)
_VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", re.ASCII)
_ADOPTED = re.compile(r"adopted-[1-9][0-9]*", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_TOKEN = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}", re.ASCII)
_PART = re.compile(r"[a-zA-Z0-9_.-]+", re.ASCII)
_RESERVED = {"CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$"}
_RESERVED.update(f"{prefix}{i}" for prefix in ("COM", "LPT") for i in range(1, 10))
_MANIFEST_FIELDS = {
    "schema_version", "package_type", "package_id", "version", "platform", "source_commit",
    "build_id", "minimum_updater", "compatibility", "migrations", "deletions",
    "restart_profile", "files",
}
_UPDATE_FIELDS = {"component", "from_version", "to_version", "image", "required_free_disk", "compose_delta", "config_delta"}
_PLUGIN_FIELDS = {"plugin_id", "plugin_version", "core_api", "ui_api", "handlers"}


class PackageError(ValueError):
    """A package or external policy failed closed; messages contain no payload data."""


def updater_files(version):
    """The running source literal selects its own exact authenticated inventory."""
    if version in {"1.0.0", "1.0.1"}:
        return UPDATER_FILES
    if version == "1.1.0":
        return UPDATER_CLOSURE_FILES
    raise PackageError("update_unsupported_updater_release")


def require_complete_updater():
    """The bridge supports only updater transition and console recovery."""
    if UPDATER_RELEASE_VERSION == "1.0.1":
        raise PackageError("update_updater_transition_required")


def updater_inventory_profile(names) -> str:
    """Classify only fixed exact inventories; this is not package admission."""
    if not isinstance(names, (list, tuple, set, frozenset, dict)) or any(
        not isinstance(name, str) for name in names
    ):
        raise PackageError("update_unsupported_updater_inventory")
    inventory = frozenset(names)
    if len(inventory) != len(names):
        raise PackageError("update_unsupported_updater_inventory")
    if inventory == UPDATER_FILES:
        return "legacy-17"
    if inventory == UPDATER_CLOSURE_FILES:
        return "closure-22"
    raise PackageError("update_unsupported_updater_inventory")


def updater_transition_diagnostic(manifest, current_version) -> str:
    """Read-only candidate planning, NOT signature verification or admission.

    Callers must never treat a matching contract as permission to execute code.
    Verification authenticates the entire package separately. The component
    enforces the launcher gate before any mutation and rechecks the launcher
    and current pointer under lock before activation.
    """
    if not isinstance(manifest, dict):
        return "update_unsupported_updater_release"
    minimum = manifest.get("minimum_updater")
    if type(minimum) is not int or minimum != UPDATER_VERSION:
        return "update_incompatible_updater"
    target = manifest.get("to_version")
    if not isinstance(target, str) or target not in UPDATER_TRANSITION_RELEASES:
        return "update_unsupported_updater_release"
    source, expected_profile = UPDATER_TRANSITION_RELEASES[target]
    rows = manifest.get("files")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        return "update_unsupported_updater_inventory"
    try:
        profile = updater_inventory_profile([row.get("path") for row in rows])
    except PackageError:
        return "update_unsupported_updater_inventory"
    if profile != expected_profile:
        return "update_unsupported_updater_inventory"
    if profile == "closure-22" and current_version != source:
        return "update_bridge_required"
    if manifest.get("from_version") != source or current_version != source:
        return "update_source_version_mismatch"
    return "update_launcher_check_required" if profile == "closure-22" else "update_bridge_contract_matches"


@dataclass(frozen=True)
class PackageLimits:
    max_archive_bytes: int = 256 * 1024 * 1024
    max_entries: int = 20000
    max_file_bytes: int = 128 * 1024 * 1024
    max_total_bytes: int = 1024 * 1024 * 1024
    max_manifest_bytes: int = 8 * 1024 * 1024
    max_ratio: int = 200


@dataclass(frozen=True)
class ImageLimits:
    max_layer_bytes: int = 128 * 1024 * 1024
    max_total_bytes: int = 1024 * 1024 * 1024
    max_entries: int = 20000
    max_layers: int = 128
    max_ratio: int = 200


@dataclass(frozen=True)
class VerifiedPackage:
    manifest: dict[str, Any]
    archive_sha256: str
    manifest_sha256: str
    key_id: str
    total_bytes: int
    archive_bytes: bytes = field(repr=False, compare=False)

    def summary(self) -> dict[str, Any]:
        return {
            "status": "verified", "package_type": self.manifest["package_type"],
            "package_id": self.manifest["package_id"], "version": self.manifest["version"],
            "source_commit": self.manifest["source_commit"], "key_id": self.key_id,
            "archive_sha256": self.archive_sha256, "manifest_sha256": self.manifest_sha256,
            "files_count": len(self.manifest["files"]), "total_bytes": self.total_bytes,
            "installed": False, "executed": False,
            "verification_scope": "signature_and_contents_only",
        }


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise PackageError("duplicate JSON key")
        result[key] = value
    return result


def _invalid_constant(_value):
    raise PackageError("floating-point and non-finite JSON values are not supported")


def read_json(raw: bytes, *, object_only: bool = True) -> Any:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=_invalid_constant, parse_float=_invalid_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise PackageError("invalid JSON document") from exc
    if object_only and not isinstance(value, dict):
        raise PackageError("expected a JSON object")
    return value


def _fields(value: Any, expected: set[str]) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise PackageError("missing or unsupported fields")


def _match(pattern, value) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def safe_package_path(name: str) -> str:
    """Reject Windows aliases on every host; never repair an untrusted path."""
    if not isinstance(name, str) or not name or len(name) > 220:
        raise PackageError("invalid package path")
    for part in name.split("/"):
        if (not _match(_PART, part) or part in {".", ".."} or part.endswith(".")
                or part.split(".", 1)[0].upper() in _RESERVED or len(part) > 120):
            raise PackageError("unsafe or ambiguous package path")
    return name


def _bounded_read(path: Path, limit: int, *, single_link: bool = False) -> bytes:
    # This is a bounded snapshot, not a future install authorization or a promise
    # that the pathname continues to refer to the same file after this call.
    try:
        with path.open("rb") as stream:
            if single_link:
                opened = os.fstat(stream.fileno())
                if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                    raise PackageError("source and signing-key hard links are not allowed")
            value = stream.read(limit + 1)
    except OSError as exc:
        raise PackageError("cannot read package or external trust policy") from exc
    if len(value) > limit:
        raise PackageError("input size limit exceeded")
    return value


def read_archive_snapshot(package: Path, limits: PackageLimits | None = None) -> bytes:
    """Check entry count before ZipFile allocates one object per central entry.

    ZIP64, multi-disk ZIPs and appended/prefixed data are outside both schemas.
    The snapshot is bounded and remains the sole source throughout verification.
    """
    limits = limits or PackageLimits()
    raw = _bounded_read(Path(package), limits.max_archive_bytes)
    end = raw.rfind(b"PK\x05\x06", max(0, len(raw) - 65557))
    if end < 0 or end + 22 > len(raw):
        raise PackageError("missing ZIP directory")
    _, disk, cd_disk, disk_entries, entries, cd_size, offset, comment = struct.unpack_from("<4s4H2IH", raw, end)
    if (disk != 0 or cd_disk != 0 or entries != disk_entries or not 1 <= entries <= limits.max_entries
            or entries == 65535 or offset + cd_size != end or end + 22 + comment != len(raw)
            or raw[:4] != b"PK\x03\x04"):
        raise PackageError("unsupported ZIP layout or entry count")
    count = 0
    while offset < end:
        if offset + 46 > end or raw[offset:offset + 4] != b"PK\x01\x02":
            raise PackageError("invalid ZIP directory")
        fields = struct.unpack_from("<4s6H3I5H2I", raw, offset)
        count += 1
        if count > entries or fields[13] != 0 or fields[16] == 0xFFFFFFFF:
            raise PackageError("invalid ZIP entry count or offset")
        offset += 46 + fields[10] + fields[11] + fields[12]
    if offset != end or count != entries:
        raise PackageError("ZIP directory count mismatch")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            _inspect_archive(zf, limits)
    except PackageError:
        raise
    except (zipfile.BadZipFile, ValueError, NotImplementedError) as exc:
        raise PackageError("invalid ZIP archive") from exc
    return raw


def _b64(value: Any, length: int) -> bytes:
    if not isinstance(value, str):
        raise PackageError("invalid signature or public key type")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise PackageError("invalid signature or public key encoding") from exc
    if len(raw) != length or base64.b64encode(raw).decode("ascii") != value:
        raise PackageError("invalid signature or public key length")
    return raw


def _verify_signature(manifest, raw, signature, trust):
    _fields(signature, {"algorithm", "key_id", "signature"})
    if signature["algorithm"] != "ed25519" or not _match(_TOKEN, signature["key_id"]):
        raise PackageError("unsupported signature")
    _fields(trust, {"schema_version", "keys"})
    if type(trust["schema_version"]) is not int or trust["schema_version"] != 1:
        raise PackageError("unsupported trust policy")
    if not isinstance(trust["keys"], list) or not 1 <= len(trust["keys"]) <= 64:
        raise PackageError("invalid trusted key list")
    by_id = {}
    for key in trust["keys"]:
        _fields(key, {"key_id", "public_key", "package_ids", "revoked"})
        if (not _match(_TOKEN, key["key_id"]) or key["key_id"] in by_id
                or type(key["revoked"]) is not bool or not isinstance(key["package_ids"], list)
                or not key["package_ids"] or any(not _match(_TOKEN, p) for p in key["package_ids"])):
            raise PackageError("invalid trusted key policy")
        _b64(key["public_key"], 32)
        by_id[key["key_id"]] = key
    key = by_id.get(signature["key_id"])
    if key is None or key["revoked"] or manifest.get("package_id") not in key["package_ids"]:
        raise PackageError("signer unknown, revoked or not authorized for package")
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise PackageError("cryptography verifier dependency is not installed") from exc
    try:
        Ed25519PublicKey.from_public_bytes(_b64(key["public_key"], 32)).verify(
            _b64(signature["signature"], 64), SIGNING_CONTEXT + raw,
        )
    except InvalidSignature as exc:
        raise PackageError("invalid package signature") from exc


def _manifest_fields(manifest):
    schema = manifest.get("schema_version")
    if type(schema) is not int or schema not in {1, 2}:
        raise PackageError("unsupported manifest schema")
    extra = _PLUGIN_FIELDS if schema == 2 and manifest.get("component") == "plugin" else set()
    if schema == 2 and "recovery_profile" in manifest:
        extra = extra | {"recovery_profile"}
    _fields(manifest, _MANIFEST_FIELDS | (_UPDATE_FIELDS if schema == 2 else set()) | extra)
    return schema


def _version(value):
    if not _match(_VERSION, value):
        raise PackageError("invalid version")
    return tuple(map(int, value.split(".")))


def _validate_update(manifest):
    component = manifest["component"]
    if "recovery_profile" in manifest:
        if (component != "server" or manifest["recovery_profile"] not in
                ("ui-only", "postgres", "history", "files", "full")):
            raise PackageError("update_invalid_recovery_profile")
        if (manifest["recovery_profile"] == "ui-only"
                and any(manifest[key] is not None for key in ("compose_delta", "config_delta"))):
            raise PackageError("update_invalid_recovery_profile")
    if not isinstance(component, str) or component not in {"server", "agent", "updater", "plugin"}:
        raise PackageError("update_component_mismatch")
    installing = component == "server" and manifest["package_type"] == "core-install"
    expected = ("plugin-update", manifest["plugin_id"], "plugin-only") if component == "plugin" else {
        "server": ("core-install" if installing else "core-update", "sli.core", "docker-compose"),
        "agent": ("plugin-update", "sli.agent", "none"),
        "updater": ("plugin-update", "sli.updater", "none"),
    }[component]
    if (manifest["package_type"], manifest["package_id"], manifest["restart_profile"]) != expected:
        raise PackageError("update_component_mismatch")
    compatibility = manifest["compatibility"]
    if (manifest["from_version"] != compatibility["from_version"] or manifest["to_version"] != manifest["version"]
            or (installing and manifest["from_version"] is not None)
            or (not installing and not _match(_ADOPTED, manifest["from_version"])
                and _version(manifest["from_version"]) >= _version(manifest["to_version"]))):
        raise PackageError("update_incompatible_version")
    adopted = _match(_ADOPTED, manifest["from_version"])
    if adopted and (component != "server" or compatibility["min_version"] != manifest["from_version"]
                    or compatibility["max_version"] != manifest["from_version"]):
        raise PackageError("update_incompatible_version")
    if not adopted and _version(compatibility["min_version"]) > _version(compatibility["max_version"]):
        raise PackageError("update_incompatible_version")
    if (compatibility["os"] not in ("linux", "windows") or compatibility["architecture"] not in ("amd64", "arm64")
            or manifest["platform"] != compatibility["os"] + "-" + compatibility["architecture"]
            or (component in {"server", "plugin"} and compatibility["os"] != "linux")):
        raise PackageError("update_incompatible_platform")
    if type(manifest["required_free_disk"]) is not int or manifest["required_free_disk"] <= 0:
        raise PackageError("update_invalid_disk_requirement")
    migrations = manifest["migrations"]
    if not isinstance(migrations, dict):
        raise PackageError("update_invalid_migration_inventory")
    identities = {}
    for name, checksum in migrations.items():
        safe_package_path(name)
        if not _match(_SHA256, checksum):
            raise PackageError("update_invalid_migration_id")
        # This source-owned role bootstrap is checksummed with the image, but
        # has no version in the migration ledger.
        if component == "server" and name == "config/postgres_migrations/storage_v2_roles.sql":
            continue
        # Both rollback spellings exist in immutable, applied source history.
        # Strip the suffix before matching so _rollback cannot become a forward
        # migration stem, and aliases still share one rollback identity.
        rollback = re.search(r"(?:\.|_)rollback\.sql$", name)
        forward_name = name[:rollback.start()] + ".sql" if rollback else name
        match = re.fullmatch(r"config/postgres_migrations/([0-9]+)_([A-Za-z0-9_]+)\.sql", forward_name)
        if match is None:
            raise PackageError("update_invalid_migration_id")
        identity = (int(match[1]), rollback is not None)
        if identity in identities:
            raise PackageError("update_duplicate_migration_id")
        identities[identity] = match[2]
    for (number, rollback), stem in identities.items():
        if rollback and identities.get((number, False)) != stem:
            raise PackageError("update_invalid_migration_id")
    if component == "server":
        image = manifest["image"]
        _fields(image, {"path", "digest"})
        safe_package_path(image["path"])
        if not isinstance(image["digest"], str) or not image["digest"].startswith("sha256:") or not _match(_SHA256, image["digest"][7:]):
            raise PackageError("update_invalid_image_digest")
        paths = [image["path"]]
        for key in ("compose_delta", "config_delta"):
            if manifest[key] is not None:
                paths.append(safe_package_path(manifest[key]))
        if len(set(paths)) != len(paths) or set(paths) != {item["path"] for item in manifest["files"]}:
            raise PackageError("update_inventory_mismatch")
    elif component == "plugin":
        if (not _match(re.compile(r"sli\.[a-z][a-z0-9-]*"), manifest["plugin_id"])
                or manifest["plugin_id"] in {"sli.core", "sli.agent"}
                or manifest["plugin_version"] != manifest["version"]
                or any(manifest[key] is not None for key in ("image", "compose_delta", "config_delta"))):
            raise PackageError("update_invalid_plugin_payload")
        for name in ("core_api", "ui_api"):
            _fields(manifest[name], {"minimum", "maximum_exclusive"})
            if not _version(manifest[name]["minimum"]) <= (1, 0, 0) < _version(manifest[name]["maximum_exclusive"]):
                raise PackageError("update_plugin_api_incompatible")
        handlers = manifest["handlers"]
        if (not isinstance(handlers, list) or not handlers or len(handlers) > 64
                or any(not _match(_TOKEN, handler) for handler in handlers) or len(set(handlers)) != len(handlers)):
            raise PackageError("update_invalid_plugin_handlers")
        paths = {item["path"] for item in manifest["files"]}
        if not {"backend/registration.py", "backend/jobs-v3.json", "ui/descriptor.json"} <= paths or any(
                not path.startswith(("backend/", "ui/")) for path in paths):
            raise PackageError("update_invalid_plugin_payload")
    elif migrations or any(manifest[key] is not None for key in ("image", "compose_delta", "config_delta")):
        raise PackageError("update_invalid_agent_payload")
    if component == "updater":
        contract = UPDATER_TRANSITION_RELEASES.get(manifest["to_version"])
        if contract is None or manifest["from_version"] != contract[0]:
            raise PackageError("update_unsupported_updater_release")
        if (compatibility["os"] != "linux"
                or {item["path"] for item in manifest["files"]} != updater_files(manifest["to_version"])):
            raise PackageError("update_invalid_updater_payload")


def validate_manifest(manifest: dict[str, Any], limits: PackageLimits) -> None:
    schema = _manifest_fields(manifest)
    kind = manifest["package_type"]
    if kind not in ("core-install", "core-update", "plugin-install", "plugin-update"):
        raise PackageError("unsupported package type")
    plugin = kind.startswith("plugin-")
    package_id = manifest["package_id"]
    if (not _match(_TOKEN, package_id) or (package_id != "sli.core" and not plugin)
            or (plugin and (not package_id.startswith("sli.") or package_id == "sli.core"))):
        raise PackageError("invalid package ownership")
    if not _match(_VERSION, manifest["version"]) or not _match(_TOKEN, manifest["build_id"]):
        raise PackageError("invalid version or build identity")
    if not _match(re.compile(r"[0-9a-f]{40}"), manifest["source_commit"]):
        raise PackageError("full source commit required")
    if schema == 1 and manifest["platform"] != "windows-x64":
        raise PackageError("unsupported target platform")
    if type(manifest["minimum_updater"]) is not int or manifest["minimum_updater"] != UPDATER_VERSION:
        raise PackageError("unsupported updater requirement")
    compatibility = manifest["compatibility"]
    agent_range = schema == 2 and manifest.get("component") == "agent" and isinstance(compatibility, dict) and "agent_api" in compatibility
    optional = {"migration_ledger_max", "plugins"} & set(compatibility) if isinstance(compatibility, dict) and schema == 2 else set()
    _fields(compatibility, {"core_api", "ui_api", "from_version"} | ({"min_version", "max_version", "os", "architecture"} if schema == 2 else set()) | optional | ({"agent_api"} if agent_range else set()))
    if agent_range:
        api = compatibility["agent_api"]
        _fields(api, {"min", "max"})
        if any(type(api[k]) is not int or api[k] < 1 for k in ("min", "max")) or api["min"] > api["max"]:
            raise PackageError("update_invalid_agent_api")
    if "migration_ledger_max" in optional:
        if type(compatibility["migration_ledger_max"]) is not int or compatibility["migration_ledger_max"] < 0:
            raise PackageError("update_invalid_ledger_expectation")
    if "plugins" in optional:
        plugins = compatibility["plugins"]
        if not isinstance(plugins, dict):
            raise PackageError("update_invalid_plugin_compatibility")
        for plugin_id, policy in plugins.items():
            if not _match(_TOKEN, plugin_id):
                raise PackageError("update_invalid_plugin_compatibility")
            _fields(policy, {"min_version", "max_version", "enabled"})
            if type(policy["enabled"]) is not bool or _version(policy["min_version"]) > _version(policy["max_version"]):
                raise PackageError("update_invalid_plugin_compatibility")
    for name in ("core_api", "ui_api"):
        if type(compatibility[name]) is not int or compatibility[name] != 1:
            raise PackageError("unsupported API contract")
    previous = compatibility["from_version"]
    if kind.endswith("-install"):
        if previous is not None:
            raise PackageError("install cannot declare an update base")
    elif not (schema == 2 and manifest.get("component") == "server" and _match(_ADOPTED, previous)) and (
            not _match(_VERSION, previous) or _version(previous) >= _version(manifest["version"])):
        raise PackageError("update requires an exact earlier version")
    # V1 is verification-only; v2 activation belongs to the component lifecycle.
    # Neither schema authorizes deletions or unchecked source-file replacement.
    if manifest["deletions"] != [] or (schema == 1 and (manifest["migrations"] != [] or manifest["restart_profile"] != "none")):
        raise PackageError("migration, deletion or runtime activation is not supported")
    files = manifest["files"]
    if not isinstance(files, list) or not 1 <= len(files) <= limits.max_entries - 2:
        raise PackageError("invalid file inventory")
    total = 0
    seen = {}
    file_names = set()
    for item in files:
        _fields(item, {"path", "size", "sha256"})
        path = safe_package_path(item["path"])
        parts = path.split("/")
        for i in range(1, len(parts) + 1):
            prefix = "/".join(parts[:i])
            folded = prefix.casefold()
            if folded in seen and seen[folded] != prefix:
                raise PackageError("case-insensitive path collision")
            seen[folded] = prefix
            if i < len(parts) and folded in file_names:
                raise PackageError("file and directory collision")
        folded = path.casefold()
        if folded in file_names or any(p.startswith(folded + "/") for p in seen):
            raise PackageError("duplicate or conflicting file path")
        file_names.add(folded)
        if schema == 1 and plugin:
            if parts[0] not in {"backend", "ui"} or len(parts) < 2:
                raise PackageError("plugin payload exceeds its owned roots")
        elif schema == 1:
            from scripts.apply_project_zip import is_allowed

            if not is_allowed(path):
                raise PackageError("core payload exceeds immutable source roots")
        if type(item["size"]) is not int or not 0 <= item["size"] <= limits.max_file_bytes or not _match(_SHA256, item["sha256"]):
            raise PackageError("invalid file digest or size")
        total += item["size"]
    if total > limits.max_total_bytes:
        raise PackageError("uncompressed size limit exceeded")
    if schema == 2:
        _validate_update(manifest)


def _check_installation(manifest, installed, free_bytes, total_bytes, component):
    if manifest["schema_version"] != 2:
        raise PackageError("update_runtime_schema_unsupported")
    if manifest["component"] != component or component != installed["component"]:
        raise PackageError("update_component_mismatch")
    compatible = manifest["compatibility"]
    if manifest["package_type"].endswith("-install"):
        raise PackageError("update_install_package_forbidden")
    adopted = _match(_ADOPTED, installed["version"])
    if (manifest["from_version"] != installed["version"] or (adopted and not
            compatible["min_version"] == installed["version"] == compatible["max_version"]) or (not adopted and not
            _version(compatible["min_version"]) <= _version(installed["version"]) <= _version(compatible["max_version"]))):
        raise PackageError("update_incompatible_version")
    if any(compatible[key] != installed[key] for key in ("os", "architecture")):
        raise PackageError("update_incompatible_platform")
    if component == "agent" and "agent_api" in compatible:
        api = compatible["agent_api"]
        if not api["min"] <= installed.get("agent_api", 1) <= api["max"]:
            raise PackageError("update_incompatible_agent_api")
    if type(free_bytes) is not int or free_bytes < max(manifest["required_free_disk"], 3 * total_bytes):
        raise PackageError("update_insufficient_disk")
    if component == "plugin":
        if installed.get("plugin_id") != manifest["plugin_id"]:
            raise PackageError("update_component_mismatch")
        for name in ("core_api", "ui_api"):
            current = _version(installed[name])
            if not _version(manifest[name]["minimum"]) <= current < _version(manifest[name]["maximum_exclusive"]):
                raise PackageError("update_plugin_api_incompatible")
        # Plugin migrations use the global PostgreSQL ledger and immutable IDs.
        # New SQL needs the core maintenance/checkpoint lifecycle; never run it
        # during a plugin-only rollback which must leave other writers running.
        if manifest["migrations"] != installed.get("migrations", {}):
            raise PackageError("update_plugin_migration_requires_core_maintenance")
        return
    old = installed.get("migrations", {})
    if manifest.get("recovery_profile") in {"ui-only", "history", "files"} and manifest["migrations"] != old:
        raise PackageError("update_recovery_profile_requires_postgres")
    for name, checksum in old.items():
        if manifest["migrations"].get(name) != checksum:
            raise PackageError("update_published_migration_changed")
    newest = max((int(PurePosixPath(name).name.split("_", 1)[0]) for name in old
                  if PurePosixPath(name).name.split("_", 1)[0].isdigit()), default=0)
    for name in manifest["migrations"].keys() - old.keys():
        if name == "config/postgres_migrations/storage_v2_roles.sql":
            continue
        if int(PurePosixPath(name).name.split("_", 1)[0]) <= newest:
            raise PackageError("update_published_migration_id_reused")


def _inspect_archive(zf: zipfile.ZipFile, limits: PackageLimits):
    entries = zf.infolist()
    if not 1 <= len(entries) <= limits.max_entries:
        raise PackageError("archive entry count limit")
    names = set()
    total = 0
    for info in entries:
        safe_package_path(info.orig_filename)
        name = info.filename
        if name.casefold() in names or info.is_dir():
            raise PackageError("duplicate entry or directory metadata")
        names.add(name.casefold())
        mode = stat.S_IFMT(info.external_attr >> 16)
        if mode not in (0, stat.S_IFREG) or info.external_attr & 0x400 or info.flag_bits & 1:
            raise PackageError("link, reparse, special or encrypted archive entry")
        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise PackageError("unsupported compression")
        if (info.file_size > limits.max_file_bytes or info.compress_size < 0
                or info.file_size > max(1, info.compress_size) * limits.max_ratio):
            raise PackageError("archive expansion limit")
        total += info.file_size
    if total > limits.max_total_bytes + limits.max_manifest_bytes + 4096:
        raise PackageError("archive total size limit")


def verify_package(package: Path, trust_store: Path, *, limits: PackageLimits | None = None,
                   installed: dict | None = None, free_bytes: int | None = None, component: str = "server") -> VerifiedPackage:
    limits = limits or PackageLimits()
    raw = read_archive_snapshot(Path(package), limits)
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            _inspect_archive(zf, limits)
            if zf.getinfo(MANIFEST_NAME).file_size > limits.max_manifest_bytes or zf.getinfo(SIGNATURE_NAME).file_size > 4096:
                raise PackageError("metadata size limit")
            manifest_raw = zf.read(MANIFEST_NAME)
            manifest = read_json(manifest_raw)
            if canonical_json(manifest) != manifest_raw:
                raise PackageError("manifest must use canonical JSON")
            signature = read_json(zf.read(SIGNATURE_NAME))
            trust = read_json(_bounded_read(Path(trust_store), 64 * 1024))
            _verify_signature(manifest, manifest_raw, signature, trust)
            validate_manifest(manifest, limits)
            expected = {MANIFEST_NAME, SIGNATURE_NAME} | {"payload/" + f["path"] for f in manifest["files"]}
            if set(zf.namelist()) != expected:
                raise PackageError("archive contents differ from signed inventory")
            for item in manifest["files"]:
                info = zf.getinfo("payload/" + item["path"])
                if info.file_size != item["size"]:
                    raise PackageError("file size differs from signed inventory")
                digest = hashlib.sha256()
                count = 0
                with zf.open(info) as stream:
                    while chunk := stream.read(1024 * 1024):
                        count += len(chunk)
                        if count > item["size"]:
                            raise PackageError("file expands beyond signed size")
                        digest.update(chunk)
                if count != item["size"] or digest.hexdigest() != item["sha256"]:
                    raise PackageError("file hash differs from signed inventory")
    except (zipfile.BadZipFile, KeyError, NotImplementedError, RuntimeError, RecursionError, zlib.error) as exc:
        raise PackageError("invalid release archive") from exc
    total = sum(f["size"] for f in manifest["files"])
    if installed is not None:
        _check_installation(manifest, installed, free_bytes, total, component)
    return VerifiedPackage(manifest, hashlib.sha256(raw).hexdigest(), hashlib.sha256(manifest_raw).hexdigest(), signature["key_id"], total, raw)


def extract_payload(verified: VerifiedPackage, destination: Path) -> None:
    """Stage only the authenticated snapshot, never reopen its mutable pathname."""
    destination = Path(destination)
    with zipfile.ZipFile(io.BytesIO(verified.archive_bytes)) as archive:
        for item in verified.manifest["files"]:
            path = destination / item["path"]
            if not path.resolve().is_relative_to(destination.resolve()):
                raise PackageError("unsafe staging path")
            path.parent.mkdir(parents=True, exist_ok=True)
            for part in (path.parent, *path.parent.parents):
                if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
                    raise PackageError("staging links are not allowed")
                if part == destination:
                    break
            if path.exists() or path.is_symlink():
                body = _bounded_read(_plain_source(path, destination), item["size"], single_link=True)
                if len(body) != item["size"] or hashlib.sha256(body).hexdigest() != item["sha256"]:
                    raise PackageError("staged payload changed")
                continue
            import tempfile

            descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".payload-")
            try:
                with archive.open("payload/" + item["path"]) as source, os.fdopen(descriptor, "wb") as target:
                    while chunk := source.read(1024 * 1024):
                        target.write(chunk)
                    target.flush()
                    os.fsync(target.fileno())
                os.replace(temporary, path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)


def _plain_source(path: Path, root: Path) -> Path:
    try:
        if not path.resolve(strict=True).is_relative_to(root.resolve(strict=True)):
            raise PackageError("source must be inside input root")
        for part in (path, *path.parents):
            if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
                raise PackageError("source links and reparse points are not allowed")
            if part == root:
                break
        if not path.is_file():
            raise PackageError("source must be a regular file")
    except OSError as exc:
        raise PackageError("source is missing or inaccessible") from exc
    return path


def build_package(root: Path, output: Path, metadata: dict[str, Any], *, signing_key: Path, key_id: str) -> dict[str, Any]:
    """Build an explicit inventory, never scan a checkout for release contents.

    The private key is an operator-protected external file with 32 raw Ed25519
    bytes. It is read once, never logged, copied or included in the package.
    This builder does not assert installation closure or source provenance.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    limits = PackageLimits()
    root = Path(root).absolute()
    output = Path(output).absolute()
    if signing_key.resolve().is_relative_to(root.resolve()) or not _match(_TOKEN, key_id):
        raise PackageError("signing key must be external to input root with a valid key ID")
    if output.resolve().is_relative_to(root.resolve()):
        raise PackageError("output must be outside the input root")
    key_raw = _bounded_read(signing_key, 32, single_link=True)
    if len(key_raw) != 32:
        raise PackageError("expected a raw Ed25519 private key")
    # Copy through JSON so caller metadata cannot be changed while signing.
    manifest = read_json(canonical_json(metadata))
    _manifest_fields(manifest)
    inventory = manifest["files"]
    if not isinstance(inventory, list) or not 1 <= len(inventory) <= limits.max_entries - 2:
        raise PackageError("explicit file inventory required")
    payload = {}
    total = 0
    for entry in inventory:
        if not isinstance(entry, dict) or "path" not in entry:
            raise PackageError("explicit file path required")
        path = safe_package_path(entry["path"])
        if path in payload:
            raise PackageError("duplicate source file")
        body = _bounded_read(_plain_source(root / path, root), limits.max_file_bytes, single_link=True)
        total += len(body)
        # Build snapshots are deliberately tighter than the verifier's streamed
        # uncompressed bound, preventing aggregate in-memory growth.
        if total > limits.max_archive_bytes // 2:
            raise PackageError("builder snapshot size limit")
        payload[path] = body
    manifest["files"] = [
        {"path": path, "size": len(body), "sha256": hashlib.sha256(body).hexdigest()}
        for path, body in sorted(payload.items())
    ]
    validate_manifest(manifest, limits)
    raw = canonical_json(manifest)
    if len(raw) > limits.max_manifest_bytes:
        raise PackageError("manifest size limit")
    signature = {
        "algorithm": "ed25519", "key_id": key_id,
        "signature": base64.b64encode(Ed25519PrivateKey.from_private_bytes(key_raw).sign(SIGNING_CONTEXT + raw)).decode("ascii"),
    }
    contents = {MANIFEST_NAME: raw, SIGNATURE_NAME: canonical_json(signature)}
    contents.update({"payload/" + p: body for p, body in payload.items()})
    buffer = io.BytesIO()
    # Stored ZIP avoids builder/verifier compression-ratio disagreement and
    # gives deterministic metadata; a later format can add bounded compression.
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as zf:
        for name, body in sorted(contents.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            zf.writestr(info, body)
    blob = buffer.getvalue()
    if len(blob) > limits.max_archive_bytes:
        raise PackageError("built archive size limit")
    output.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation preserves an existing artifact on repeated invocation.
    with output.open("xb") as stream:
        stream.write(blob)
    return {"status": "built", "package": str(output), "archive_sha256": hashlib.sha256(blob).hexdigest(), "files_count": len(payload), "installed": False}
