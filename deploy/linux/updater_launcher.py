"""Stable, operator-provisioned launcher; never replaced by updater packages."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

FILES = {
    "deploy/linux/sli_update.py", "deploy/linux/update_checkpoint.py",
    "deploy/linux/backup.py", "deploy/linux/restore_existing.py", "deploy/linux/backup_restore_check.py",
    "deploy/linux/updater_component.py", "deploy/linux/update_recovery.py",
    "deploy/linux/installation.py", "deploy/linux/adoption_probe.py",
    "scripts/maintenance/release_package.py",
    "server/sli/release_package.py",
}
LEGACY_FILES = FILES - {
    "deploy/linux/backup.py", "deploy/linux/restore_existing.py", "deploy/linux/backup_restore_check.py",
}
SECRET_FILES = {
    "deploy/linux/sli_secrets.py", "deploy/linux/secrets-manifest.json",
    "server/sli/agents/ca.py",
}
NOTIFICATION_FILES = {"server/sli/core/notification_secrets.py", "server/sli/core/secret_files.py"}
AD_CREDENTIAL_FILES = {"server/sli/core/ad_credential_secrets.py"}

# Keep the standalone launcher independent of package-controlled imports.
# Historical recovery remains exact. Closure inventory is admitted only for
# the fixed reviewed target version; packages never overwrite this launcher.
SUPPORTED_INVENTORIES = tuple(frozenset(names) for names in (
    FILES, LEGACY_FILES, FILES | SECRET_FILES, LEGACY_FILES | SECRET_FILES,
    FILES | SECRET_FILES | NOTIFICATION_FILES,
    LEGACY_FILES | SECRET_FILES | NOTIFICATION_FILES,
    FILES | SECRET_FILES | NOTIFICATION_FILES | AD_CREDENTIAL_FILES,
    LEGACY_FILES | SECRET_FILES | NOTIFICATION_FILES | AD_CREDENTIAL_FILES,
))

CLOSURE_FILES = frozenset(FILES | SECRET_FILES | NOTIFICATION_FILES | AD_CREDENTIAL_FILES | {
    "deploy/linux/installed_state.py", "deploy/linux/plugin_update.py",
    "deploy/linux/backup_activity.py", "server/sli/plugin_validation.py",
    "config/plugin_architecture_v3.json",
})


def inventory_supported(version, names):
    inventory = frozenset(names)
    # Old signed local releases may already use candidate version numbers.
    # Recovery preserves their exact inventories; NEW artifact admission lives
    # in the package verifier and remains strictly mapped to B/N profiles.
    return inventory in SUPPORTED_INVENTORIES or version == "1.1.0" and inventory == CLOSURE_FILES


def _selected_snapshot(runtime, *, previous=False):
    """Read one pointer snapshot; reject missing or modified version files."""
    runtime = Path(runtime).resolve()
    with (runtime / "state/updater.json").open("rb") as stream:
        raw = stream.read(64 * 1024 + 1)
    if len(raw) > 64 * 1024:
        raise ValueError("update_invalid_updater_pointer")
    pointer = json.loads(raw)
    if pointer.get("format_version") != 1:
        raise ValueError("update_invalid_updater_pointer")
    descriptor = pointer["previous" if previous else "current"]
    if not isinstance(descriptor, dict):
        raise ValueError("update_previous_updater_required")
    if (set(descriptor) != {"component", "version", "os", "architecture", "directory", "files"}
            or descriptor["component"] != "updater" or descriptor["os"] != "linux"
            or descriptor["architecture"] not in {"amd64", "arm64"}
            or not isinstance(descriptor["version"], str)
            or not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", descriptor["version"])
            or not isinstance(descriptor["files"], dict)):
        raise ValueError("update_invalid_updater_pointer")
    name = descriptor["directory"]
    if not isinstance(name, str) or not re.fullmatch(re.escape(descriptor["version"]) + r"-[0-9a-f]{64}", name):
        raise ValueError("update_invalid_updater_pointer")
    versions = runtime / "updater/versions"
    root = versions / name
    if (root.is_symlink() or not root.resolve().is_relative_to(versions.resolve())
            or not inventory_supported(descriptor.get("version"), descriptor["files"])):
        raise ValueError("update_invalid_updater_pointer")
    for name, digest in descriptor["files"].items():
        path = root / name
        if not path.resolve().is_relative_to(root.resolve()) or any(
            part.is_symlink() for part in (path, *path.parents) if part.is_relative_to(root)
        ):
            raise ValueError("update_updater_files_changed")
        with path.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
                raise ValueError("update_updater_files_changed")
    return root, descriptor


def selected_script(runtime, *, previous=False):
    root, _ = _selected_snapshot(runtime, previous=previous)
    return root / "deploy/linux/sli_update.py"


def inspect_compatibility(runtime, *, previous=False):
    """Validate one snapshot without executing it or changing any host state.

    This is local pointer/file integrity inspection, not signature verification
    or an activation authorization. Historical recovery inventories stay exact.
    """
    _, descriptor = _selected_snapshot(runtime, previous=previous)
    return {
        "inspection_version": 1,
        "version": descriptor["version"],
        "selection": "previous" if previous else "current",
        "files": sorted(descriptor["files"]),
        "supported_inventories": [sorted(names) for names in SUPPORTED_INVENTORIES],
        "closure_activation_supported": True,
        "closure_version": "1.1.0",
        "closure_inventory": sorted(CLOSURE_FILES),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, default=Path("/srv/sli"))
    parser.add_argument("--previous", action="store_true", help="Запустить сохранённую прежнюю версию для восстановления.")
    parser.add_argument("--inspect", action="store_true", help="Inspect selected snapshot without executing it.")
    args, command = parser.parse_known_args(argv)
    try:
        if args.inspect:
            if command:
                raise ValueError("update_inspection_arguments_invalid")
            print(json.dumps(inspect_compatibility(args.runtime, previous=args.previous), sort_keys=True))
            return 0
        script = selected_script(args.runtime, previous=args.previous)
        os.execv(sys.executable, [sys.executable, "-I", "-B", str(script), *command, "--runtime", str(args.runtime)])
    except Exception:
        print("Не удалось запустить средство обновления. Проверьте указатель; "
              "для восстановления используйте --previous.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
