"""Exact installed inventory shared by adoption, update and runtime readback."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class PackageError(ValueError):
    """Installed readback failure reported by the native readiness command."""


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def migration_checksum_variants(body):
    """Accept only LF and CRLF bytes; preserve all other bytes, including lone CR."""
    lf = body.replace(b"\r\n", b"\n")
    return {hashlib.sha256(variant).hexdigest() for variant in (lf, lf.replace(b"\n", b"\r\n"))}


def migration_checksums_match(path, source_checksum, ledger_checksum):
    if source_checksum == ledger_checksum:
        return True
    # A digest alone cannot prove newline equivalence. Pin both variants to
    # this exact inventory file, and fail closed if its bytes are unavailable.
    if not re.fullmatch(r"config/postgres_migrations/\d+_[A-Za-z0-9_]+\.sql", path):
        return False
    try:
        variants = migration_checksum_variants((ROOT / path).read_bytes())
    except OSError:
        return False
    return source_checksum in variants and ledger_checksum in variants


def require_native(condition, code):
    if not condition:
        raise PackageError(code)


def native_ledger_matches(installed, observed):
    expected = installed.get("migration_ledger")
    actual = observed.get("migration_ledger")
    require_native(isinstance(expected, list) and expected, "update_installed_ledger_required")
    require_native(isinstance(actual, list) and all(isinstance(row, dict) and type(row.get("version")) is int
            for row in actual), "update_migration_ledger_mismatch")
    versions = []
    inventory = {}
    for path, checksum in installed.get("migrations", {}).items():
        match = re.fullmatch(r"(\d+)_.*\.sql", Path(path).name)
        if match and not re.search(r"(?:\.rollback|_rollback)\.sql$", path):
            version = int(match[1])
            require_native(version not in inventory, "update_migration_ledger_mismatch")
            inventory[version] = (path, checksum)
    for row in expected:
        require_native(isinstance(row, dict) and set(row) == {"version", "name", "sha256"}
                and type(row["version"]) is int and row["version"] > 0
                and isinstance(row["name"], str) and row["name"]
                and isinstance(row["sha256"], str) and re.fullmatch(r"[a-f0-9]{64}", row["sha256"]),
                "update_migration_ledger_mismatch")
        versions.append(row["version"])
        require_native(row["version"] not in inventory or migration_checksums_match(
                    *inventory[row["version"]], row["sha256"]),
                "update_migration_ledger_mismatch")
    legacy = (observed.get("installed_release_available") is False and 179 not in versions
              and installed.get("ledger_source") == "deployed_image" and bool(installed.get("adoption")))
    comparable = actual
    if legacy:
        hashes = {row["version"]: row["sha256"] for row in expected}
        comparable = [{**row, "sha256": hashes.get(row["version"]) if row.get("sha256") is None else row["sha256"]}
                      for row in actual]
    require_native(versions == sorted(set(versions)) and set(inventory) <= set(versions)
            and comparable == expected and type(observed.get("migration_ledger_max")) is int
            and observed["migration_ledger_max"] == max(versions), "update_migration_ledger_mismatch")
    return {"max_version": max(versions), "sha256": hashlib.sha256(canonical_json(actual)).hexdigest()}


def inventory(installed):
    keys = ("version", "image_tag", "image_digest", "build_id", "source_commit", "migrations", "migration_ledger")
    return {**{key: installed.get(key) for key in keys}, "plugins": {
        key: {field: value.get(field) for field in ("version", "generation", "migrations")}
        for key, value in installed.get("plugins", {}).items()}}


def installation_key(installed):
    require_native(isinstance(installed.get("compose_project"), str) and installed["compose_project"]
            and isinstance(installed.get("volumes"), dict),
            "update_foreign_installation")
    return hashlib.sha256(canonical_json({"project": installed["compose_project"], "volumes": installed["volumes"]})).hexdigest()


def registry_matches(installed, observed):
    registry = observed.get("installed_release")
    if registry is not None:
        require_native(registry.get("installation_key") == installation_key(installed), "update_foreign_installation")
        require_native(registry.get("inventory") == inventory(installed), "update_installed_registry_mismatch")


def plugins_match(installed, observed):
    rows = observed.get("plugins", [])
    active = {row["plugin_id"]: row for row in rows if row["installed"]}
    require_native(len(active) == sum(bool(row["installed"]) for row in rows), "update_plugin_registry_mismatch")
    expected = installed.get("plugins", {})
    require_native(set(active) == set(expected) and all(active[key]["version"] == value["version"]
            for key, value in expected.items()), "update_plugin_registry_mismatch")


def _pointers_match(runtime, installed, parse_json, validate_payload):
    for plugin_id, previous in installed.get("plugins", {}).items():
        require_native(re.fullmatch(r"sli\.[a-z0-9-]+", plugin_id), "update_plugin_inventory_required")
        directory = Path(runtime) / "plugins" / plugin_id
        require_native(not any(path.is_symlink() for path in (Path(runtime) / "plugins", directory, directory / "versions")),
                "update_plugin_pointer_mismatch")
        pointer = directory / "active.json"
        generation = previous.get("generation")
        if generation is None:
            require_native(not pointer.exists() and not pointer.is_symlink(), "update_plugin_pointer_mismatch")
            continue
        require_native(isinstance(generation, str) and re.fullmatch(r"[a-f0-9]{64}", generation)
                and pointer.is_file() and not pointer.is_symlink(), "update_plugin_pointer_mismatch")
        require_native(parse_json(pointer.read_bytes()) == {"generation": generation}, "update_plugin_pointer_mismatch")
        release = directory / "versions" / generation
        require_native(not release.is_symlink() and not (release / "release.json").is_symlink(),
                "update_plugin_pointer_mismatch")
        manifest = parse_json((release / "release.json").read_bytes())
        require_native(manifest["plugin_id"] == plugin_id and manifest["plugin_version"] == previous["version"],
                "update_plugin_pointer_mismatch")
        validate_payload(release, manifest)


def native_pointers_match(runtime, installed):
    from deploy.linux.native_plugin_payload import read_json, validate_payload

    _pointers_match(runtime, installed, read_json, validate_payload)


def validate(installed, observed, runtime=None, *, registry=True):
    native_ledger_matches(installed, observed)
    require_native(observed.get("services") and all(
        row["image_digest"] == installed["image_digest"] and row["image_tag"] == installed["image_tag"]
        and (row["version"] == installed["version"] or (row["version"] is None
             and installed.get("adoption") and installed["version"].startswith("adopted-")))
        for row in observed["services"].values()), "update_running_version_mismatch")
    plugins_match(installed, observed)
    if registry:
        registry_matches(installed, observed)
    if runtime is not None:
        native_pointers_match(runtime, installed)
