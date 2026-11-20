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


def selected_script(runtime, *, previous=False):
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
    name = descriptor["directory"]
    if not isinstance(name, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+-[0-9a-f]{64}", name):
        raise ValueError("update_invalid_updater_pointer")
    versions = runtime / "updater/versions"
    root = versions / name
    if (root.is_symlink() or not root.resolve().is_relative_to(versions.resolve())
            or set(descriptor["files"]) not in (
                FILES, LEGACY_FILES, FILES | SECRET_FILES, LEGACY_FILES | SECRET_FILES,
                FILES | SECRET_FILES | NOTIFICATION_FILES,
                LEGACY_FILES | SECRET_FILES | NOTIFICATION_FILES,
                FILES | SECRET_FILES | NOTIFICATION_FILES | AD_CREDENTIAL_FILES,
                LEGACY_FILES | SECRET_FILES | NOTIFICATION_FILES | AD_CREDENTIAL_FILES)):
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
    return root / "deploy/linux/sli_update.py"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, default=Path("/srv/sli"))
    parser.add_argument("--previous", action="store_true", help="Запустить сохранённую прежнюю версию для восстановления.")
    args, command = parser.parse_known_args(argv)
    try:
        script = selected_script(args.runtime, previous=args.previous)
        os.execv(sys.executable, [sys.executable, "-I", "-B", str(script), *command, "--runtime", str(args.runtime)])
    except Exception:
        print("Не удалось запустить средство обновления. Проверьте указатель; "
              "для восстановления используйте --previous.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
