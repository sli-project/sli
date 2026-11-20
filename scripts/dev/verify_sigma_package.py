"""Validate the stage-01 Sigma package offline; never evaluate event data."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path, PurePosixPath
from uuid import UUID
from zipfile import ZipFile


CONFIG = Path(__file__).resolve().parents[2] / "config/sigma"
if __package__ in (None, "") and str(CONFIG.parent.parent) not in sys.path:
    sys.path.insert(0, str(CONFIG.parent.parent))
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_RULE_BYTES = 1024 * 1024


class PackageError(ValueError):
    """An input does not match the reviewed package."""


@dataclass(frozen=True, repr=False)
class VerifiedRule:
    id: str
    raw_yaml: bytes
    author: str
    source_uri: str
    license: str
    upstream_commit: str


def _check_hash(raw: bytes, expected: str) -> None:
    if hashlib.sha256(raw).hexdigest() != expected:
        raise PackageError("SHA-256 mismatch")


def _relative_path(value: str) -> str:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or "\\" in value:
        raise PackageError("Invalid package-relative path")
    return value


def load_config(config: Path = CONFIG) -> tuple[dict, dict]:
    lock = json.loads((config / "lock.json").read_bytes())
    if lock["schema_version"] != 1 or lock["stage"] != 1:
        raise PackageError("Unsupported lock schema or stage")
    parser = lock["parser"]
    license_info = lock["upstream"]["license"]
    files = [
        (lock["profile"]["path"], lock["profile"]["sha256"]),
        (parser["requirements_path"], parser["requirements_sha256"]),
        (parser["software_manifest_path"], parser["software_manifest_sha256"]),
        (parser["license_path"], parser["license_sha256"]),
        (license_info["text_path"], license_info["text_sha256"]),
    ]
    for path, digest in files:
        _check_hash((config / _relative_path(path)).read_bytes(), digest)
    profile = json.loads((config / lock["profile"]["path"]).read_bytes())
    entries = lock["rules"]
    ids = [entry["id"] for entry in entries]
    paths = [entry["path"] for entry in entries]
    if len(ids) != 25 or len(set(ids)) != 25 or len(set(paths)) != 25:
        raise PackageError("Expected 25 unique rule UUIDs and paths")
    if any(str(UUID(rule_id)) != rule_id for rule_id in ids):
        raise PackageError("Noncanonical rule UUID")
    if (
        profile["schema_version"] != 1
        or profile["upstream_commit"] != lock["upstream"]["commit"]
        or [entry["id"] for entry in profile["rules"]] != ids
        or any(entry["priority"] not in (1, 2) for entry in profile["rules"])
    ):
        raise PackageError("Profile does not match the pinned selection")
    return lock, profile


def verify_package(archive: Path, config: Path = CONFIG) -> tuple[VerifiedRule, ...]:
    lock, _ = load_config(config)
    if version(lock["parser"]["distribution"]) != lock["parser"]["version"]:
        raise PackageError("Installed parser version does not match the lock")
    if archive.stat().st_size > MAX_ARCHIVE_BYTES:
        raise PackageError("Archive exceeds the size limit")
    # The reviewed lock is the trust boundary. Check original archive bytes
    # before parsing; hashes alone do not authenticate the publisher.
    raw_archive = archive.read_bytes()
    _check_hash(raw_archive, lock["upstream"]["archive"]["sha256"])

    from io import BytesIO

    from server.sli.sigma.cache_policy import prepare_sigma_caches

    prepare_sigma_caches()
    from sigma.collection import SigmaCollection

    upstream = lock["upstream"]
    root = _relative_path(upstream["archive"]["root"])
    verified = []
    with ZipFile(BytesIO(raw_archive)) as package:
        names = package.namelist()
        if len(names) != len(set(names)):
            raise PackageError("Duplicate archive entries")

        def read_member(path: str, digest: str) -> bytes:
            name = f"{root}/{_relative_path(path)}"
            try:
                info = package.getinfo(name)
            except KeyError:
                raise PackageError("Required package member is missing") from None
            if info.file_size > MAX_RULE_BYTES:
                raise PackageError("Package member exceeds the size limit")
            raw = package.read(info)
            _check_hash(raw, digest)
            return raw

        license_info = upstream["license"]
        if license_info["id"] != "DRL-1.1":
            raise PackageError("Unexpected upstream license")
        read_member(license_info["path"], license_info["sha256"])
        for entry in lock["rules"]:
            if entry["license"] != license_info["id"]:
                raise PackageError("Unexpected rule license")
            source_uri = f"{upstream['repository']}/blob/{upstream['commit']}/{entry['path']}"
            if entry["source_uri"] != source_uri:
                raise PackageError("Rule source URI does not match the pinned commit")
            raw = read_member(entry["path"], entry["sha256"])
            try:
                collection = SigmaCollection.from_yaml(raw)
                if len(collection.rules) != 1:
                    raise ValueError("Expected one atomic rule")
                rule = collection.rules[0]
                # pySigma parses conditions lazily. Force validation, not matching.
                for condition in rule.detection.parsed_condition:
                    condition.parsed
            except Exception:
                # Parser diagnostics can contain original author/field values.
                raise PackageError(f"Invalid Sigma YAML for UUID {entry['id']}") from None
            if str(rule.id) != entry["id"]:
                raise PackageError("Rule UUID does not match the manifest")
            if not isinstance(rule.author, str) or not rule.author.strip():
                raise PackageError("Rule attribution is missing")
            if rule.license not in (None, license_info["id"]):
                raise PackageError("Unexpected YAML license override")
            verified.append(VerifiedRule(
                id=entry["id"], raw_yaml=raw, author=rule.author,
                source_uri=source_uri, license=entry["license"],
                upstream_commit=upstream["commit"],
            ))
    return tuple(verified)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    args = parser.parse_args()
    try:
        rules = verify_package(args.archive)
    except Exception:
        # Do not emit paths or arbitrary metadata from external packages.
        print("Sigma stage 01: FAILED (package, manifest or parser mismatch)")
        return 1
    print(f"Sigma stage 01: verified {len(rules)} YAML rules, hashes, UUIDs and attribution; no evaluation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
