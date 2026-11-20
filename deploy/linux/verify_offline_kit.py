"""Read-only completeness check; package authentication remains the trusted verifier's job."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import tarfile
from pathlib import Path, PurePosixPath


class KitError(ValueError):
    """Stable reason codes, never file contents or operator paths."""


def require(condition, code):
    if not condition:
        raise KitError(code)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def plain_file(root, name):
    require(isinstance(name, str) and name and "\\" not in name and ":" not in name,
            "kit_invalid_path")
    parts = PurePosixPath(name).parts
    require(not name.startswith("/") and "/".join(parts) == name
            and all(part not in {".", ".."} for part in parts), "kit_invalid_path")
    path = root
    for part in parts:
        path = path / part
        require(not path.is_symlink(), "kit_link_forbidden")
    require(path.is_file() and stat.S_ISREG(path.stat().st_mode), "kit_file_missing")
    return path


def file_inventory(root):
    result = []
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink(), "kit_link_forbidden")
        if path.is_dir():
            continue
        name = path.relative_to(root).as_posix()
        if name == "KIT_INVENTORY.json":
            continue
        plain_file(root, name)
        result.append({"path": name, "size": path.stat().st_size, "sha256": digest(path)})
    return result


WORKSTATION_MANIFEST = "config/plugin_packages/v3/sli.workstations.json"
WORKSTATION_FILES = (
    WORKSTATION_MANIFEST,
    "config/postgres_migrations/159_workstation_security.sql",
    "config/postgres_migrations/160_agent_workstation_dispatch.sql",
    "sli_agent/workstations.py",
    "sli_agent/modules.py",
)
INTERNAL_LABEL = "не для выпуска"


def _workstation_files(root):
    required = set(WORKSTATION_FILES)
    try:
        manifest = json.loads(plain_file(root, WORKSTATION_MANIFEST).read_text("utf-8"))
        require(isinstance(manifest, dict) and manifest.get("plugin_id") == "sli.workstations",
                "release_workstations_manifest_invalid")
        migrations = manifest["data"]["migrations"]
        require(isinstance(migrations, list) and migrations, "release_workstations_migrations_missing")
        for migration in migrations:
            name = migration["path"]
            require(type(migration["version"]) is int and migration["version"] >= 159
                    and isinstance(name, str) and re.fullmatch(r"config/postgres_migrations/[0-9]+_[a-z0-9_]+\.sql", name)
                    and int(PurePosixPath(name).name.split("_", 1)[0]) == migration["version"],
                    "release_workstations_manifest_invalid")
            # Match the existing migration contract across Git CRLF checkouts.
            checksum = hashlib.sha256(plain_file(root, name).read_bytes().replace(b"\r\n", b"\n")).hexdigest()
            require(checksum == migration["sha256"],
                    "release_workstations_migration_mismatch")
            required.add(name)
        for name in required:
            require(plain_file(root, name).stat().st_size > 0, "release_workstations_file_empty")
    except (KitError, OSError, ValueError, KeyError, TypeError):
        raise KitError("release_workstations_incomplete") from None
    return required


def _workstation_image(image, root, required):
    expected = {"opt/sli/" + name: digest(root / name) for name in required}
    actual = {}
    with tarfile.open(image, "r:*") as archive:
        records = json.load(archive.extractfile("manifest.json"))
        require(isinstance(records, list) and len(records) == 1, "release_workstations_image_invalid")
        for name in records[0]["Layers"]:
            with tarfile.open(fileobj=archive.extractfile(name), mode="r|*") as layer:
                for entry in layer:
                    path = entry.name.removeprefix("./")
                    # Fail closed if a layer hides a required file or directory.
                    parent, _, leaf = path.rpartition("/")
                    if leaf.startswith(".wh."):
                        hidden = parent if leaf == ".wh..wh..opq" else (parent + "/" + leaf[4:]).lstrip("/")
                        require(not any(not hidden or target == hidden or target.startswith(hidden + "/")
                                        for target in expected), "release_workstations_image_whiteout")
                    if path in expected:
                        require(entry.isfile(), "release_workstations_image_invalid")
                        actual[path] = hashlib.file_digest(layer.extractfile(entry), "sha256").hexdigest()
                    elif any(target.startswith(path + "/") for target in expected):
                        require(entry.isdir(), "release_workstations_image_invalid")
    require(actual == expected, "release_workstations_image_incomplete")


def workstation_release_gate(root, *, internal_test_build=False, image=None):
    """Check shipped files, never runtime activation or a database."""
    failures = []
    try:
        required = _workstation_files(root)
        if image is not None:
            _workstation_image(image, root, required)
    except KitError as exc:
        failures.append(str(exc))
    except (OSError, ValueError, KeyError, TypeError, AttributeError, tarfile.TarError):
        failures.append("release_workstations_image_invalid" if image is not None else "release_workstations_incomplete")
    if failures and not internal_test_build:
        raise KitError(failures[0])
    return {"status": "internal_test" if internal_test_build else "passed",
            "release_eligible": not internal_test_build,
            "artifact_label": INTERNAL_LABEL if internal_test_build else "release",
            "failures": failures}


def kit_release_gate(kit, *, internal_test_build=False, check_image=False):
    inputs = json.loads((kit / "release-inputs.json").read_text("utf-8"))
    eligible = inputs.get("release_eligible", True)
    require(type(eligible) is bool, "release_build_marker_invalid")
    if not eligible:
        require(inputs.get("artifact_label") == INTERNAL_LABEL, "release_build_marker_invalid")
        require(internal_test_build, "release_internal_test_not_for_release")
    for path in (kit / "manifests").glob("*.unsigned.json"):
        draft = json.loads(path.read_text("utf-8"))
        prefix = "release-" if eligible else "internal-test-not-for-release-"
        require(draft.get("build_id") == prefix + inputs["version"], "release_build_marker_invalid")
    # A verifier flag cannot turn an unmarked incomplete kit into a test build.
    return workstation_release_gate(kit / "source", internal_test_build=not eligible,
                                    image=kit / "images/server.tar" if check_image else None)


def docker_archive(path, tag):
    """Inspect Docker-save metadata without extracting or executing image files."""
    with tarfile.open(path, "r:*") as archive:
        members = archive.getmembers()
        names = {item.name: item for item in members}
        require(len(names) == len(members), "kit_image_duplicate_member")
        for item in members:
            require(not item.name.startswith("/") and ".." not in PurePosixPath(item.name).parts
                    and (item.isfile() or item.isdir()), "kit_image_invalid_member")
        def read(name):
            item = names.get(name)
            require(item is not None and item.isfile() and item.size <= 1024 * 1024, "kit_image_metadata_missing")
            with archive.extractfile(item) as stream:
                return stream.read()
        manifest = json.loads(read("manifest.json"))
        require(isinstance(manifest, list) and len(manifest) == 1, "kit_image_count_mismatch")
        record = manifest[0]
        require(tag in record.get("RepoTags", []) and record.get("Layers")
                and all(name in names and names[name].isfile() for name in record["Layers"]), "kit_image_incomplete")
        raw = read(record["Config"])
        config = json.loads(raw)
        require(config.get("os") == "linux" and config.get("architecture") == "amd64", "kit_image_platform_mismatch")
        labels = config.get("config", {}).get("Labels") or {}
        return {"tag": tag, "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                "version": labels.get("org.opencontainers.image.version"),
                "source_commit": labels.get("org.opencontainers.image.revision")}


def verify(kit, trust_store=None, *, internal_test_build=False, evaluation=False, inventory_sha256=None):
    kit = kit.resolve(strict=True)
    inventory_path = plain_file(kit, "KIT_INVENTORY.json")
    inventory_raw = inventory_path.read_bytes()
    if evaluation:
        require(isinstance(inventory_sha256, str) and re.fullmatch(r"[0-9a-f]{64}", inventory_sha256),
                "kit_inventory_sha256_required")
        require(hashlib.sha256(inventory_raw).hexdigest() == inventory_sha256, "kit_inventory_sha256_mismatch")
    inventory = json.loads(inventory_raw)
    unsigned = inventory.get("signing") == "evaluation-unsigned"
    require(not unsigned or evaluation, "kit_evaluation_flag_required")
    require(not evaluation or unsigned, "kit_evaluation_marker_required")
    if not evaluation:
        require(trust_store is not None, "kit_trust_policy_missing")
        require(not trust_store.is_symlink(), "kit_trust_link_forbidden")
        trust_store = trust_store.resolve(strict=True)
        require(not trust_store.is_relative_to(kit), "kit_trust_must_be_external")
        trust = json.loads(trust_store.read_text("utf-8"))
        require(trust.get("schema_version") == 1 and isinstance(trust.get("keys"), list)
                and any(key.get("revoked") is False and "sli.core" in key.get("package_ids", [])
                        for key in trust["keys"]), "kit_trust_policy_missing")
    require(inventory.get("schema_version") == 1 and inventory.get("stage") == "offline"
            and re.fullmatch(r"[0-9a-f]{40}", inventory.get("source_commit", "")), "kit_not_finalized")
    require(inventory.get("files") == file_inventory(kit), "kit_inventory_mismatch")
    names = {item["path"] for item in inventory["files"]}
    required = {
        "verify_offline_kit.py", "build_offline_kit.sh", "release-inputs.json",
        "START_HERE.md", "docs/install/SERVER_INSTALL.ru.md", "docs/install/SERVER_INSTALL.en.md",
        "docs/agent-enrollment.md",
        "inventories/licenses.json", "inventories/sbom.json", "RELEASE_NOTES.md",
        "inventories/source.json", "host-requirements.lock.txt",
        "inventories/base-images.lock", "inventories/os-packages.tsv",
        "images/server.tar", "images/postgres.tar", "images/clickhouse.tar",
        "images/metadata.json", "packages/install.zip", "manifests/install.unsigned.json",
        "source/deploy/linux/docker-compose.yml", "source/deploy/linux/init.sql",
        "source/deploy/linux/sli_update.py", "source/deploy/linux/update_checkpoint.py",
        "source/deploy/linux/sli_install.py", "source/deploy/linux/installation.py",
        "source/deploy/linux/evaluation_package.py", "source/server/sli/release_package.py",
        "source/tools/build_update_package.py", "source/scripts/maintenance/release_package.py",
        "source/config/postgres_baseline/manifest.json", "source/config/postgres_baseline/baseline.sql",
        "source/config/postgres_baseline/roles.sql", "source/requirements.lock.txt",
        "source/package-lock.json", "source/frontend/package-lock.json",
    }
    require(required <= names, "kit_incomplete")
    require(all(plain_file(kit, name).stat().st_size > 0 for name in required), "kit_empty_file")
    for minor in (11, 12, 13, 14):
        prefix = f"host-libs/python3.{minor}/"
        libraries = {prefix + name + "/__init__.py" for name in ("cryptography", "cffi", "pycparser")}
        require(libraries <= names
                and any(name.startswith(prefix + "cryptography/hazmat/bindings/_rust.")
                        and name.endswith(".so") for name in names)
                and prefix + f"_cffi_backend.cpython-3{minor}-x86_64-linux-gnu.so" in names,
                "kit_host_libraries_missing")
    inputs = json.loads((kit / "release-inputs.json").read_text("utf-8"))
    gate = kit_release_gate(kit, internal_test_build=internal_test_build, check_image=True)
    require(inventory.get("release_eligible", True) == gate["release_eligible"]
            and inventory.get("artifact_label", "release") == gate["artifact_label"], "release_build_marker_invalid")
    require(inputs["source_commit"] == inventory["source_commit"], "kit_source_mismatch")
    if inputs["from_version"] is not None and not evaluation:
        require({"packages/update.zip", "manifests/update.unsigned.json"} <= names, "kit_update_missing")
    require(json.loads((kit / "inventories/source.json").read_text("utf-8")) == file_inventory(kit / "source"),
            "kit_source_modified")
    compose = (kit / "source/deploy/linux/docker-compose.yml").read_text("utf-8")
    for reference in set(re.findall(r"\.\./\.\./(config/[A-Za-z0-9_./-]+)", compose)):
        mount = "source/" + reference
        # Compose also binds directories. Require an inventoried file or a
        # nonempty directory of inventoried, regular files; hashes were checked
        # above, and plain_file rechecks every path for links and unsafe aliases.
        mount_files = [name for name in names if name == mount or name.startswith(mount + "/")]
        require(mount_files, "kit_file_missing")
        for name in mount_files:
            plain_file(kit, name)
    migrations = {name.removeprefix("source/"): digest(kit / name) for name in names
                  if name.startswith("source/config/postgres_migrations/") and name.endswith(".sql")}
    image_file = {"path": "images/server.tar", "size": (kit / "images/server.tar").stat().st_size,
                  "sha256": digest(kit / "images/server.tar")}
    manifests = []
    for kind in (("install", "update") if inputs["from_version"] is not None else ("install",)):
        manifest = json.loads((kit / "manifests" / (kind + ".unsigned.json")).read_text("utf-8"))
        require(migrations and manifest["migrations"] == migrations, "kit_migrations_mismatch")
        require(manifest["package_type"] == "core-" + kind and manifest["package_id"] == "sli.core"
                and manifest["source_commit"] == inputs["source_commit"]
                and manifest["version"] == manifest["to_version"] == inputs["version"]
                and manifest["from_version"] == (None if kind == "install" else inputs["from_version"]),
                "kit_source_mismatch")
        require(manifest["image"]["path"] == image_file["path"]
                and manifest["files"] == [image_file], "kit_image_mismatch")
        manifests.append(manifest)
    metadata = json.loads((kit / "images/metadata.json").read_text("utf-8"))
    for name, tag in (("server", "sli-release:" + inputs["version"]), ("postgres", "postgres:18.6-bookworm"),
                      ("clickhouse", "clickhouse/clickhouse-server:25.8")):
        actual = docker_archive(kit / "images" / (name + ".tar"), tag)
        require(actual == metadata[name], "kit_image_mismatch")
    require(all(metadata["server"]["digest"] == manifest["image"]["digest"] for manifest in manifests)
            and metadata["server"]["version"] == inputs["version"]
            and metadata["server"]["source_commit"] == inputs["source_commit"], "kit_image_mismatch")
    result = {"status": "complete", "source_commit": inventory["source_commit"],
            "authenticated": False, "installed": False, "workstation_gate": gate}
    if evaluation:
        result["signing"] = "evaluation-unsigned"
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kit", type=Path, required=True)
    parser.add_argument("--trust-store", type=Path)
    parser.add_argument("--evaluation", action="store_true", help="Accept an unsigned kit for evaluation only")
    parser.add_argument("--inventory-sha256", help="Expected inventory SHA-256 from a separate trusted channel")
    parser.add_argument("--internal-test-build", action="store_true", help=INTERNAL_LABEL)
    args = parser.parse_args(argv)
    try:
        result = verify(args.kit, args.trust_store, internal_test_build=args.internal_test_build,
                        evaluation=args.evaluation, inventory_sha256=args.inventory_sha256)
    except Exception as exc:
        result = {"status": "failed", "reason_code": str(exc) if isinstance(exc, KitError)
                  else "kit_check_failed"}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
