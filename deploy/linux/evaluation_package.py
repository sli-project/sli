"""Unsigned install archives, accepted only with an explicitly pinned evaluation kit."""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import zipfile
from pathlib import Path

from deploy.linux import verify_offline_kit as kit_check
from deploy.linux.sli_update import UpdateError, require
from server.sli.release_package import (
    MANIFEST_NAME, PackageLimits, VerifiedPackage, _bounded_read, _inspect_archive,
    canonical_json, read_archive_snapshot, read_json, validate_manifest,
)


def build(kit):
    """Build the evaluation archive without loading or generating any signing key."""
    limits = PackageLimits()
    manifest = read_json(_bounded_read(kit / 'manifests/install.unsigned.json', limits.max_manifest_bytes))
    validate_manifest(manifest, limits)
    require(manifest['package_type'] == 'core-install', 'install_package_required')
    output = kit / 'packages/install.zip'
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED) as archive:
        # Keep ZIP dates valid and stable even when SOURCE_DATE_EPOCH predates
        # 1980 (Python 3.14 also applies it to newly constructed ZipInfo).
        archive.writestr(zipfile.ZipInfo(MANIFEST_NAME, (1980, 1, 1, 0, 0, 0)), canonical_json(manifest))
        for item in manifest['files']:
            path = kit_check.plain_file(kit, item['path'])
            require(path.stat().st_size == item['size'] and kit_check.digest(path) == item['sha256'],
                    'install_evaluation_payload_mismatch')
            info = zipfile.ZipInfo('payload/' + item['path'], (1980, 1, 1, 0, 0, 0))
            with path.open('rb') as source, archive.open(info, 'w') as target:
                shutil.copyfileobj(source, target)
    return output


def verify(package, kit, inventory_sha256):
    """Check integrity only; never grant signature authentication or update acceptance."""
    kit = Path(kit).resolve(strict=True)
    try:
        kit_check.verify(kit, evaluation=True, inventory_sha256=inventory_sha256)
    except kit_check.KitError as exc:
        raise UpdateError(str(exc)) from None
    inventory_raw = _bounded_read(kit / 'KIT_INVENTORY.json', 64 * 1024 * 1024)
    require(hashlib.sha256(inventory_raw).hexdigest() == inventory_sha256, 'install_evaluation_inventory_mismatch')
    inventory = json.loads(inventory_raw)
    package_path = kit_check.plain_file(kit, 'packages/install.zip')
    require(Path(package).resolve() == package_path, 'install_evaluation_package_required')
    limits = PackageLimits()
    raw = read_archive_snapshot(package_path, limits)
    entry = next((item for item in inventory['files'] if item['path'] == 'packages/install.zip'), None)
    require(entry and len(raw) == entry['size'] and hashlib.sha256(raw).hexdigest() == entry['sha256'],
            'install_evaluation_package_mismatch')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        _inspect_archive(archive, limits)
        require(archive.getinfo(MANIFEST_NAME).file_size <= limits.max_manifest_bytes,
                'install_evaluation_manifest_too_large')
        manifest_raw = archive.read(MANIFEST_NAME)
        manifest = read_json(manifest_raw)
        validate_manifest(manifest, limits)
        require(manifest_raw == canonical_json(manifest), 'install_evaluation_manifest_invalid')
        draft = kit_check.plain_file(kit, 'manifests/install.unsigned.json')
        draft_raw = _bounded_read(draft, limits.max_manifest_bytes)
        draft_entry = next(item for item in inventory['files'] if item['path'] == 'manifests/install.unsigned.json')
        require(hashlib.sha256(draft_raw).hexdigest() == draft_entry['sha256']
                and manifest == read_json(draft_raw), 'install_evaluation_manifest_mismatch')
        require(manifest['package_type'] == 'core-install', 'install_package_required')
        expected = {MANIFEST_NAME} | {'payload/' + item['path'] for item in manifest['files']}
        require(set(archive.namelist()) == expected, 'install_evaluation_archive_invalid')
        for item in manifest['files']:
            info = archive.getinfo('payload/' + item['path'])
            require(info.file_size == item['size'], 'install_evaluation_payload_mismatch')
            checksum = hashlib.sha256()
            count = 0
            with archive.open(info) as stream:
                while chunk := stream.read(1024 * 1024):
                    count += len(chunk)
                    require(count <= item['size'], 'install_evaluation_payload_mismatch')
                    checksum.update(chunk)
            require(count == item['size'] and checksum.hexdigest() == item['sha256'],
                    'install_evaluation_payload_mismatch')
    # The installer extracts this immutable, integrity-checked snapshot before
    # changing runtime or calling Docker. It has no signature authentication.
    return VerifiedPackage(manifest, hashlib.sha256(raw).hexdigest(), hashlib.sha256(manifest_raw).hexdigest(),
                           'evaluation-unsigned', sum(item['size'] for item in manifest['files']), raw)
