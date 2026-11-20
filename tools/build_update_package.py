"""Build Docker updates through the canonical SLI release-package builder."""

from __future__ import annotations

import argparse
import ast
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from deploy.linux.sli_update import image_inventory, load_deltas
from scripts.maintenance.release_package import (
    MANIFEST_NAME, PackageError, PackageLimits, _bounded_read, build_package, read_json,
    _version, _plain_source, updater_files, UPDATER_TRANSITION_RELEASES,
)

VERSION_FILE = Path(__file__).resolve().parents[1] / "VERSION"


def validate_updater_source(metadata, payload_root, profile):
    profiles = {"bridge-17": "1.0.1", "closure-22": "1.1.0"}
    version = profiles.get(profile)
    if version is None or metadata.get("to_version") != version:
        raise PackageError("update_build_updater_profile_required")
    source, _ = UPDATER_TRANSITION_RELEASES[version]
    if metadata.get("from_version") != source or metadata.get("version") != version:
        raise PackageError("update_build_version_mismatch")
    paths = [row.get("path") for row in metadata.get("files", [])]
    if len(paths) != len(set(paths)) or set(paths) != updater_files(version):
        raise PackageError("update_invalid_updater_payload")
    path = _plain_source(payload_root / "server/sli/release_package.py", payload_root)
    tree = ast.parse(_bounded_read(path, 1024 * 1024, single_link=True))
    identities = [node.value.value for node in tree.body if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name) and target.id == "UPDATER_RELEASE_VERSION"
                          for target in node.targets)
                  and isinstance(node.value, ast.Constant)]
    if identities != [version]:
        raise PackageError("update_build_version_mismatch")


def build(manifest_path: Path, payload_root: Path, key_path: Path, output: Path, *, key_id: str,
          updater_profile=None):
    metadata = read_json(_bounded_read(manifest_path, PackageLimits().max_manifest_bytes))
    if metadata.get("component") == "updater":
        validate_updater_source(metadata, payload_root, updater_profile)
    elif updater_profile is not None:
        raise PackageError("update_build_updater_profile_forbidden")
    if metadata.get("component") == "server":
        version = VERSION_FILE.read_text("utf-8").strip()
        _version(version)
        if any(metadata.get(key, version) != version for key in ("version", "to_version")):
            raise PackageError("update_build_version_mismatch")
        metadata.update(version=version, to_version=version)
    # Use the same builder as scripts/package_project.py. Validate the signed
    # snapshot rather than mutable input files before publishing.
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as temporary:
        candidate = Path(temporary) / "candidate.zip"
        build_package(payload_root, candidate, metadata, signing_key=key_path, key_id=key_id)
        with zipfile.ZipFile(candidate) as archive:
            manifest = read_json(archive.read(MANIFEST_NAME))
            if manifest["schema_version"] != 2:
                raise PackageError("update_runtime_schema_unsupported")
            directory = Path(temporary) / "payload"
            directory.mkdir()
            for item in manifest["files"]:
                path = directory / item["path"]
                path.parent.mkdir(parents=True, exist_ok=True)
                with archive.open("payload/" + item["path"]) as source, path.open("xb") as target:
                    shutil.copyfileobj(source, target)
        if manifest["component"] == "server":
            image_inventory(directory / manifest["image"]["path"], manifest, Path(temporary) / "image.tar")
            load_deltas(directory, manifest)
        elif manifest["component"] == "plugin":
            from deploy.linux.plugin_update import validate_payload
            validate_payload(directory, manifest)
        elif manifest["component"] == "updater":
            from deploy.linux.updater_component import run_selftest
            run_selftest(directory, manifest["to_version"])
        with candidate.open("rb") as source, output.open("xb") as target:
            shutil.copyfileobj(source, target)
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sign", action="store_true", help="Explicit offline signing (also the default; requires an external key)")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--payload-root", type=Path, required=True)
    parser.add_argument("--signing-key", type=Path, required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--updater-profile", choices=["bridge-17", "closure-22"])
    args = parser.parse_args(argv)
    try:
        build(args.manifest, args.payload_root, args.signing_key, args.output, key_id=args.key_id,
              updater_profile=args.updater_profile)
    except Exception:
        print("update_build_failed", file=sys.stderr)
        return 1
    print("update_package_signed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
