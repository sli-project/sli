"""Finite native plugin inventory and audited bundled VPN registration.

The baseline's v1 registry attestation predates the current manifest metadata.
Keep that exact DB attestation separate from the shipped manifest file digest.
Registration never enables acquisition or changes restored source assignments.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
from uuid import uuid4

REMOTE = "sli.remote-access"
REMOTE_MANIFEST = "sli.remote-access.package.v1"
REMOTE_HASH = "78ae9bcc2e65f54c8469dd0494f5c951df0cfa53ae33cff84478bc70eaa958bf"
REMOTE_FILE = "config/plugin_packages/sli.remote-access.json"
VERSIONS = {key: "1.0.0" for key in ("sli.ad", "sli.gpo", "sli.file-audit", "sli.workstations", "sli.sigma")}
VERSIONS[REMOTE] = "0.1.0"


def require(condition, code):
    if not condition:
        raise ValueError(code)


def manifest_checksum(root: Path) -> str:
    try:
        body = (root / REMOTE_FILE).read_bytes().replace(b"\r\n", b"\n")
        value = json.loads(body)
        require(isinstance(value, dict) and value.get("plugin_id") == REMOTE and value.get("plugin_version") == VERSIONS[REMOTE]
                and value.get("manifest_id") == REMOTE_MANIFEST, "native_plugins_asset_mismatch")
        return hashlib.sha256(body).hexdigest()
    except (OSError, json.JSONDecodeError):
        raise ValueError("native_plugins_asset_mismatch") from None


def release_inventory(root: Path, plugins: dict) -> dict:
    """Finalize the shipped inventory before the Debian release is sealed."""
    require(isinstance(plugins, dict) and set(plugins) in (set(VERSIONS), set(VERSIONS) - {REMOTE})
            and all(isinstance(value, dict) and value.get("version") == VERSIONS[key] for key, value in plugins.items()),
            "native_plugins_inventory_mismatch")
    remote = {"version": VERSIONS[REMOTE], "migrations": {}, "manifest_id": REMOTE_MANIFEST,
              "manifest_sha256": REMOTE_HASH, "manifest_file": REMOTE_FILE,
              "manifest_file_sha256": manifest_checksum(root)}
    if REMOTE in plugins:
        require(all(plugins[REMOTE].get(key, value) == value for key, value in remote.items()),
                "native_plugins_inventory_mismatch")
        require(plugins[REMOTE].get("generation") is None, "native_plugins_inventory_mismatch")
    return {**plugins, REMOTE: remote}


def verify_registry(root: Path, plugins: dict, rows: list) -> None:
    """Readiness never adopts unknown plugins, versions or VPN attestations."""
    require(isinstance(plugins, dict) and set(plugins) <= set(VERSIONS)
            and all(isinstance(value, dict) and value.get("version") == VERSIONS[key] for key, value in plugins.items())
            and isinstance(rows, list) and all(isinstance(row, (list, tuple)) and len(row) == 3 for row in rows)
            and len(rows) == len({row[0] for row in rows})
            and {row[0]: row[1] for row in rows} == {key: value["version"] for key, value in plugins.items()},
            "native_plugins_mismatch")
    if REMOTE in plugins:
        remote = plugins[REMOTE]
        require(remote.get("manifest_id") == REMOTE_MANIFEST and remote.get("manifest_sha256") == REMOTE_HASH
                and remote.get("manifest_file") == REMOTE_FILE
                and remote.get("manifest_file_sha256") == manifest_checksum(root)
                and next(row[2] for row in rows if row[0] == REMOTE) == REMOTE_HASH,
                "native_plugins_manifest_mismatch")


def bootstrap(connection) -> None:
    """Promote only the known validated seed through migration 074's executor.

    The native migrate advisory lock serializes retries. The executor owns the
    optimistic revision check and append-only audit in the same transaction.
    Already registered databases retain their owner's activation settings.
    """
    from server.sli.sources.plugin_lifecycle import initial_remote_access_state, plan_plugin_lifecycle

    with connection.transaction():
        row = connection.execute(
            "SELECT manifest_id, manifest_sha256, package_version, package_lifecycle, "
            "desired_activation, component_runtime, queue_state, revision "
            "FROM public.plugin_installations_v1 WHERE plugin_id=%s", (REMOTE,),
        ).fetchone()
        require(row and tuple(row[:3]) == (REMOTE_MANIFEST, REMOTE_HASH, VERSIONS[REMOTE]),
                "native_plugins_bootstrap_mismatch")
        if row[3] == "registered":
            return
        require(tuple(row[3:7]) == ("validated", "disabled", "stopped", "drained")
                and type(row[7]) is int and row[7] > 0, "native_plugins_bootstrap_mismatch")
        plan = plan_plugin_lifecycle(action="install", state=replace(initial_remote_access_state(), revision=row[7]),
                                     actor_capabilities={"plugins.manage"})
        result = connection.execute(
            "SELECT operation_id, committed_revision, package_lifecycle, desired_activation "
            "FROM public.execute_bundled_plugin_install_v1(%s::uuid,%s,%s::bigint,%s,%s,%s,%s)",
            (str(uuid4()), REMOTE, row[7], plan["plan_sha256"], plan["confirmation"], "system", "native-bootstrap"),
        ).fetchone()
        require(result and result[0] > 0 and tuple(result[1:]) == (row[7] + 1, "registered", "disabled"),
                "native_plugins_bootstrap_readback_mismatch")
