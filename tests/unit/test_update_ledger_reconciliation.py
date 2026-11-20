"""Signed recovery of an applied ledger ahead of image inventory, without a DB."""
from __future__ import annotations

import copy
import hashlib
import zipfile

import pytest

from deploy.linux import sli_update as update
from server.sli import release_package as package
from tests.unit.test_sli_update import build, make_image, release  # noqa: F401


def ahead(release, *, crlf=False):
    updater, host, archive, manifest, key, payload = release
    body = b"insert into schema_migrations(version,name) values(2,'later');\n"
    path = "config/postgres_migrations/002_later.sql"
    image, migrations = make_image(payload / "image.tar", extra={"opt/sli/" + path: body})
    manifest = {**manifest, "image": image, "migrations": {**migrations, path: hashlib.sha256(body).hexdigest()},
                "files": [{"path": "image.tar"}],
                "compatibility": {**manifest["compatibility"], "migration_ledger_max": 2}}
    draft = payload / "draft.json"
    draft.write_bytes(package.canonical_json(manifest))
    archive.unlink()
    build(draft, payload, payload.parent / "offline.key", archive, key_id="test-only")
    row = {"version": 2, "name": "later", "sha256": hashlib.sha256(
        body.replace(b"\n", b"\r\n") if crlf else body).hexdigest()}
    host.ledger = 2
    host.exact_ledger = [*copy.deepcopy(host.installed["migration_ledger"]), row]
    return updater, host, archive


@pytest.mark.parametrize("crlf", [False, True])
def test_reconcile_then_normal_update_preserves_real_ledger_and_image_inventory(release, crlf, monkeypatch):
    updater, host, archive = ahead(release, crlf=crlf)
    if crlf:
        from deploy.linux import installed_state
        source = updater.runtime / "source"
        migration = source / "config/postgres_migrations/002_later.sql"
        migration.parent.mkdir(parents=True)
        migration.write_bytes(b"insert into schema_migrations(version,name) values(2,'later');\n")
        monkeypatch.setattr(installed_state, "ROOT", source)
    previous = copy.deepcopy(host.installed)
    actual = copy.deepcopy(host.exact_ledger)
    assert updater.reconcile(archive) == "reconciled"
    installed = package.read_json(updater.installed_path.read_bytes())
    assert installed == {**previous, "migration_ledger": actual}
    assert host.exact_ledger == actual
    assert not {"stage", "drain", "migrate", "activate", "checkpoint"} & set(host.calls)
    host.installed = installed
    assert updater.apply(archive) == "committed"
    assert host.exact_ledger == actual


@pytest.mark.parametrize("attack", ["old_hash", "old_name", "new_hash", "new_name", "unknown", "duplicate", "order"])
def test_reconcile_rejects_foreign_or_changed_ledger_before_publication(release, attack):
    updater, host, archive = ahead(release)
    before = updater.installed_path.read_bytes()
    if attack == "old_hash":
        host.exact_ledger[0]["sha256"] = "f" * 64
    elif attack == "old_name":
        host.exact_ledger[0]["name"] = "foreign"
    elif attack == "new_hash":
        host.exact_ledger[-1]["sha256"] = "f" * 64
    elif attack == "new_name":
        host.exact_ledger[-1]["name"] = "foreign"
    elif attack == "unknown":
        host.exact_ledger.append({"version": 3, "name": "foreign", "sha256": "f" * 64})
    elif attack == "duplicate":
        host.exact_ledger.append(copy.deepcopy(host.exact_ledger[-1]))
    else:
        host.exact_ledger.reverse()
    with pytest.raises(package.PackageError, match="migration_ledger_mismatch"):
        updater.reconcile(archive)
    assert updater.installed_path.read_bytes() == before
    assert "publish" not in host.calls


def test_reconcile_dry_run_does_not_publish_or_write_intent(release):
    updater, host, archive = ahead(release)
    before = updater.installed_path.read_bytes()
    assert updater.reconcile(archive, dry_run=True) == "verified"
    assert updater.installed_path.read_bytes() == before
    assert not updater.reconciliation_path.exists()
    assert "publish" not in host.calls


def test_reconcile_signature_precedes_host_access(release):
    updater, host, archive = ahead(release)
    updater.trust_store.write_text('{"schema_version":1,"keys":[]}')
    with pytest.raises(package.PackageError):
        updater.reconcile(archive)
    assert host.calls == []


def test_reconcile_retries_after_registry_commit_before_cache_replace(release, monkeypatch):
    updater, host, archive = ahead(release)
    original = update.atomic_json
    failed = False

    def interrupt(path, value):
        nonlocal failed
        if path == updater.installed_path and not failed:
            failed = True
            raise OSError("synthetic cache failure")
        return original(path, value)

    monkeypatch.setattr(update, "atomic_json", interrupt)
    with pytest.raises(OSError):
        updater.reconcile(archive)
    assert host.installed_release["inventory"]["migration_ledger"] == host.exact_ledger
    with pytest.raises(package.PackageError, match="update_reconciliation_required"):
        updater.apply(archive)
    assert updater.reconcile(archive) == "reconciled"
    assert updater.read_journal(updater.reconciliation_path)["status"] == "committed"


def test_reconcile_rejects_unrelated_registry(release):
    updater, host, archive = ahead(release)
    host.installed_release = {"installation_key": "foreign", "inventory": {}}
    with pytest.raises(package.PackageError, match="registry_mismatch|foreign_installation"):
        updater.reconcile(archive)
    assert "publish" not in host.calls


def test_reconciled_update_can_roll_back_to_attested_previous_state(release):
    updater, host, archive = ahead(release)
    assert updater.reconcile(archive) == "reconciled"
    previous = updater.installed_path.read_bytes()
    host.installed = package.read_json(previous)
    host.fail = "health"
    assert updater.apply(archive) == "rolled_back"
    assert updater.installed_path.read_bytes() == previous
    assert host.exact_ledger == host.installed["migration_ledger"]


@pytest.mark.parametrize("rollback_only", [False, True])
def test_next_package_cannot_omit_reconciled_forward_migrations(release, rollback_only):
    updater, host, archive = ahead(release)
    assert updater.reconcile(archive) == "reconciled"
    host.installed = package.read_json(updater.installed_path.read_bytes())
    with zipfile.ZipFile(archive) as package_file:
        manifest = package.read_json(package_file.read("SLI_RELEASE.json"))
    manifest["migrations"].pop("config/postgres_migrations/002_later.sql")
    if rollback_only:
        manifest["migrations"]["config/postgres_migrations/002_later.rollback.sql"] = "a" * 64
    with pytest.raises(package.PackageError, match="migration_ledger_mismatch"):
        updater.preflight(host.installed, manifest)


def test_runtime_readback_ignores_unnumbered_role_helper(release):
    updater, host, archive, manifest, key, payload = release
    host.active = "candidate"
    host.staged_manifest = manifest
    host.running_tag = "sli-update:candidate-test"
    journal = {"previous": host.installed, "services": ["api", "backup", "semantic"],
               "candidate_tag": host.running_tag, "candidate_ledger": host.installed["migration_ledger"],
               "manifest": {**manifest, "migrations": {**manifest["migrations"],
                   "config/postgres_migrations/storage_v2_roles.sql": "a" * 64}}}
    assert update.DockerHost.runtime_matches(host, journal)["migration_ledger_max"] == 1


@pytest.mark.parametrize("already_published", [False, True])
def test_signed_update_accepts_unnumbered_helper_without_treating_it_as_migration(release, already_published):
    updater, host, archive, manifest, key, payload = release
    helper = "config/postgres_migrations/storage_v2_roles.sql"
    body = b"select 1;"
    checksum = hashlib.sha256(body).hexdigest()
    image, migrations = make_image(payload / "image.tar", extra={"opt/sli/" + helper: body})
    manifest = {**manifest, "image": image, "migrations": {**migrations, helper: checksum},
                "files": [{"path": "image.tar"}]}
    draft = payload / "draft.json"
    draft.write_bytes(package.canonical_json(manifest))
    archive.unlink()
    build(draft, payload, payload.parent / "offline.key", archive, key_id="test-only")
    installed = copy.deepcopy(host.installed)
    if already_published:
        installed["migrations"][helper] = checksum
    verified = package.verify_package(archive, updater.trust_store, installed=installed, free_bytes=10**9)
    assert verified.manifest["migrations"][helper] == checksum
    assert updater.preflight(installed, verified.manifest)["migration_ledger_max"] == 1
    if already_published:
        installed["migrations"][helper] = "f" * 64
        with pytest.raises(package.PackageError, match="update_published_migration_changed"):
            package.verify_package(archive, updater.trust_store, installed=installed, free_bytes=10**9)
