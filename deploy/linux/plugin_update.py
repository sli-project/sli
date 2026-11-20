"""Journaled plugin-only activation; core state and database are never restored."""
from __future__ import annotations

import json
from pathlib import Path
import os
import shutil
import uuid

from scripts.maintenance.release_package import PackageError, extract_payload, verify_package
from server.sli.plugin_validation import HandlerRegistry, validate_descriptor

PHASES = ("verify", "stage", "drain", "activate", "health", "commit")


def require(condition, code):
    if not condition:
        raise PackageError(code)


def installed_plugin(core, manifest):
    plugin_id = manifest["plugin_id"]
    previous = core.get("plugins", {}).get(plugin_id)
    require(isinstance(previous, dict), "update_plugin_inventory_required")
    return {**previous, "component": "plugin", "plugin_id": plugin_id,
            "os": core["os"], "architecture": core["architecture"],
            "core_api": core.get("core_api", "1.0.0"), "ui_api": core.get("ui_api", "1.0.0")}


def verify(updater, package, core):
    verified = verify_package(package, updater.trust_store)
    manifest = verified.manifest
    require(manifest.get("component") == "plugin", "update_component_mismatch")
    previous = installed_plugin(core, manifest)
    verified = verify_package(package, updater.trust_store, installed=previous, component="plugin",
                              free_bytes=shutil.disk_usage(updater.state).free)
    manifest = verified.manifest
    # Plugin ownership is a subset of the immutable core/global SQL inventory.
    require(all(core.get("migrations", {}).get(path) == checksum
                for path, checksum in manifest["migrations"].items()), "update_published_migration_changed")
    return verified


def validate_payload(path, manifest):
    from scripts.maintenance.release_package import read_json, _plain_source
    from deploy.linux.sli_update import sha256
    for item in manifest["files"]:
        local = _plain_source(path / item["path"], path)
        require(local.stat().st_size == item["size"] and sha256(local) == item["sha256"], "update_plugin_payload_changed")
    descriptor = validate_descriptor(read_json((path / "ui/descriptor.json").read_bytes()), manifest["plugin_id"])
    files = {row["path"]: row for row in manifest["files"]}
    entry = files.get("ui/" + descriptor["entry"]["path"])
    require(entry is not None and entry["sha256"] == descriptor["entry"]["sha256"]
            and entry["size"] <= 4 * 1024 * 1024
            and descriptor["version"] == manifest["plugin_version"]
            and {name for name in files if name.startswith("ui/")} == {"ui/descriptor.json", entry["path"]},
            "update_plugin_ui_mismatch")
    jobs = read_json((path / "backend/jobs-v3.json").read_bytes())
    HandlerRegistry().register(jobs)
    require(jobs["plugin_id"] == manifest["plugin_id"] and jobs["plugin_version"] == manifest["plugin_version"]
            and {row["handler_id"] for row in jobs["handlers"]} == set(manifest["handlers"]),
            "update_plugin_handler_mismatch")
    # Handler resource/rights profiles stay under the reviewed core allowlist.
    # UI and server API ranges are declared by one signed owner.
    require(jobs["core_api"] == manifest["core_api"], "update_plugin_api_incompatible")


def base(updater, journal):
    return updater.runtime / "plugins" / journal["manifest"]["plugin_id"]


def write_pointer(path, value):
    from deploy.linux.sli_update import atomic_json
    atomic_json(path, value)
    # No secrets live in plugin descriptors. Non-root, read-only containers
    # must be able to read host-created generation pointers and manifests.
    path.chmod(0o644)


def desired(journal, previous=False):
    return journal["previous_plugin"] if previous else {
        "version": journal["manifest"]["plugin_version"], "generation": journal["package_sha256"],
        "migrations": journal["manifest"]["migrations"]}


def commit(updater, journal, previous=False):
    import copy
    core = copy.deepcopy(journal["previous"])
    # Preserve core and every other plugin, also during operator rollback.
    core.setdefault("plugins", {})[journal["manifest"]["plugin_id"]] = desired(journal, previous)
    candidate = copy.deepcopy(journal["previous"])
    candidate["plugins"][journal["manifest"]["plugin_id"]] = desired(journal)
    return updater.publish(journal, core, previous=candidate if previous else journal["previous"])


def apply(updater, verified, core, operation_id):
    from deploy.linux.sli_update import atomic_json, sha256
    operation = operation_id or uuid.uuid4().hex
    directory = updater.state / "updates" / operation
    directory.mkdir(parents=True)
    package = directory / "package.zip"
    with package.open("xb") as stream:
        stream.write(verified.archive_bytes)
        stream.flush()
        os.fsync(stream.fileno())
    manifest = verified.manifest
    journal = {"format_version": 1, "component": "plugin", "operation": operation, "status": "running",
               "phase": "verify", "completed": [], "manifest": manifest, "previous": core,
               "previous_plugin": core["plugins"][manifest["plugin_id"]], "package": str(package.resolve()),
               "package_sha256": sha256(package), "directory": str(directory.resolve()), "reason": None,
               "compose_files": {str(path): sha256(path) for path in updater.host.files},
               "desired_activation": {"plugin_id": manifest["plugin_id"], "version": manifest["plugin_version"]},
               "package_version": manifest["plugin_version"]}
    updater.save(journal)
    return run(updater, journal)


def validate_resume(updater, journal):
    from deploy.linux.sli_update import parse_json, sha256
    require(journal["phase"] in PHASES and journal["format_version"] == 1, "update_invalid_journal")
    require({str(path): sha256(path) for path in updater.host.files} == journal["compose_files"], "update_compose_changed")
    current = parse_json(updater.installed_path.read_bytes())
    expected = json.loads(json.dumps(journal["previous"]))
    expected["plugins"][journal["manifest"]["plugin_id"]] = desired(journal)
    require(current in (journal["previous"], expected), "update_installed_state_changed")
    require(sha256(journal["package"]) == journal["package_sha256"], "update_package_changed")
    require(verify(updater, journal["package"], journal["previous"]).manifest == journal["manifest"], "update_package_changed")
    updater.recovery_authority(journal, expected)
    if journal["phase"] in {"verify", "stage"}:
        updater.host.plugin_preflight(updater.runtime, journal["previous"], journal["manifest"])


def run(updater, journal):
    from deploy.linux.sli_update import reason_code
    manifest = journal["manifest"]
    directory = Path(journal["directory"])
    plugin = base(updater, journal)
    try:
        for phase in PHASES:
            if phase in journal["completed"]:
                continue
            journal["phase"] = phase
            updater.save(journal)
            if phase == "verify":
                verified = verify(updater, journal["package"], journal["previous"])
                extract_payload(verified, directory / "payload")
                validate_payload(directory / "payload", manifest)
                updater.host.plugin_preflight(updater.runtime, journal["previous"], manifest)
            elif phase == "stage":
                validate_payload(directory / "payload", manifest)
                destination = plugin / "versions" / journal["package_sha256"]
                if not destination.exists():
                    shutil.copytree(directory / "payload", destination)
                validate_payload(destination, manifest)
                for item in manifest["files"]:
                    path = destination / item["path"]
                    path.chmod(0o644)
                    parent = path.parent
                    while parent != destination:
                        parent.chmod(0o755)
                        parent = parent.parent
                destination.chmod(0o755)
                write_pointer(destination / "release.json", manifest)
                plugin.mkdir(parents=True, exist_ok=True)
                (plugin / "admission.lock").touch(exist_ok=True)
            elif phase == "drain":
                write_pointer(plugin / "draining.json", {"operation": journal["operation"]})
                updater.host.plugin_drain(updater.runtime, manifest)
            elif phase == "activate":
                validate_payload(plugin / "versions" / journal["package_sha256"], manifest)
                write_pointer(plugin / "active.json", {"generation": journal["package_sha256"]})
            elif phase == "health":
                updater.host.plugin_health(updater.runtime, manifest)
            elif phase == "commit":
                journal["observed_runtime"] = commit(updater, journal)
            journal["completed"].append(phase)
            updater.save(journal)
        journal["status"] = "committed"
        updater.save(journal)
        (plugin / "draining.json").unlink(missing_ok=True)
        return "committed"
    except Exception as exc:
        if journal["phase"] == "verify":
            journal.update(status="rejected", reason=reason_code(exc, "update_plugin_verification_failed"))
            updater.save(journal)
            return "rejected"
        return rollback(updater, journal, reason_code(exc, "update_plugin_phase_failed"))


def rollback(updater, journal, reason):
    plugin = base(updater, journal)
    journal.update(status="rolling_back", reason=reason)
    updater.save(journal)
    try:
        if "stage" in journal["completed"] or journal["phase"] == "stage":
            import copy
            candidate = copy.deepcopy(journal["previous"])
            candidate["plugins"][journal["manifest"]["plugin_id"]] = desired(journal)
            updater.recovery_authority(journal, candidate)
            plugin.mkdir(parents=True, exist_ok=True)
            (plugin / "admission.lock").touch(exist_ok=True)
            write_pointer(plugin / "draining.json", {"operation": journal["operation"]})
            updater.host.plugin_drain(updater.runtime, journal["manifest"])
            previous = journal["previous_plugin"].get("generation")
            if previous:
                write_pointer(plugin / "active.json", {"generation": previous})
            else:
                (plugin / "active.json").unlink(missing_ok=True)
            updater.host.plugin_health(updater.runtime, {**journal["manifest"],
                                                       "plugin_version": journal["previous_plugin"]["version"]})
            commit(updater, journal, previous=True)
        journal.update(status="rolled_back", desired_activation=journal["previous_plugin"])
        updater.save(journal)
        (plugin / "draining.json").unlink(missing_ok=True)
        return "rolled_back"
    except Exception:
        journal["rollback_error"] = "update_plugin_rollback_failed"
        updater.save(journal)
        raise PackageError("update_plugin_rollback_failed") from None
