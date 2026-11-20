"""Native PostgreSQL inventory contracts; no server or credentials required."""

import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import native_pg_inventory as subject

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def source(tmp_path):
    migrations = tmp_path / "config/postgres_migrations"
    migrations.mkdir(parents=True)
    (tmp_path / "config/postgres_schema_v8.sql").write_bytes(
        b"INSERT INTO schema_migrations(version,name) VALUES (1,'base') ON CONFLICT(version) DO NOTHING;\n"
    )
    (migrations / "002_second.sql").write_bytes(
        b"INSERT INTO schema_migrations(version,name) VALUES (2,'second');\n"
    )
    (migrations / "002_second.rollback.sql").write_bytes(b"SELECT 'rollback';\n")
    (migrations / "storage_v2_roles.sql").write_bytes(b"SELECT 'roles';\n")
    return tmp_path


def test_manifest_covers_rollback_and_roles_but_ledger_only_forward(source):
    manifest = subject.build_manifest(source)
    assert len(manifest["files"]) == 4
    assert manifest["hash_mode"] == "sha256-lf"
    rows = subject.expected_ledger(source)
    assert [(row["version"], row["name"]) for row in rows] == [(1, "base"), (2, "second")]
    assert rows[1]["sha256"] == hashlib.sha256(
        (source / "config/postgres_migrations/002_second.sql").read_bytes()
    ).hexdigest()
    subject.verify_manifest(source, manifest)


@pytest.mark.parametrize("change", ["edit", "missing", "extra"])
def test_manifest_rejects_sql_drift(source, change):
    manifest = subject.build_manifest(source)
    target = source / "config/postgres_migrations/storage_v2_roles.sql"
    if change == "edit":
        target.write_text("SELECT 'changed';", encoding="utf-8")
    elif change == "missing":
        target.unlink()
    else:
        (target.parent / "extra.sql").write_text("SELECT 1;", encoding="utf-8")
    with pytest.raises(ValueError, match="native_pg_sql_inventory_mismatch"):
        subject.verify_manifest(source, manifest)


def test_checkout_line_endings_preserve_canonical_sql_checksum(source):
    manifest = subject.build_manifest(source)
    for path in source.rglob("*.sql"):
        path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
    subject.verify_manifest(source, manifest)


@pytest.mark.parametrize("change", ["name", "sha256", "missing", "extra", "duplicate", "null"])
def test_exact_ledger_rejects_every_partial_or_foreign_attestation(source, change):
    expected = subject.expected_ledger(source)
    rows = copy.deepcopy(expected)
    if change in {"name", "sha256"}:
        rows[0][change] = "foreign"
    elif change == "missing":
        rows.pop()
    elif change == "extra":
        rows.append({"version": 3, "name": "extra", "sha256": "0" * 64})
    elif change == "null":
        rows[0]["sha256"] = None
    else:
        rows.append(rows[0])
    with pytest.raises(ValueError, match="native_pg_ledger_mismatch"):
        subject.verify_ledger(rows, expected)


def test_readback_is_read_only_and_compares_full_ledger_using_fake(source):
    expected = subject.expected_ledger(source)
    queries = []

    def execute(query):
        queries.append(query)
        return SimpleNamespace(fetchall=lambda: [tuple(row.values()) for row in expected])

    actual = subject.read_ledger(SimpleNamespace(execute=execute))
    subject.verify_ledger(actual, expected)
    assert len(queries) == 1 and queries[0].lower().startswith("select ")
    assert "order by version" in queries[0]


def test_repository_sql_is_immutable_against_native_manifest():
    manifest = json.loads((ROOT / "deploy/linux/native_pg_ledger.json").read_text(encoding="utf-8"))
    subject.verify_manifest(ROOT, manifest)


def test_file_audit_service_filter_is_pinned_and_in_forward_ledger():
    manifest = json.loads((ROOT / "deploy/linux/native_pg_ledger.json").read_text(encoding="utf-8"))
    path = "config/postgres_migrations/288_file_audit_service_filter.sql"
    digest = hashlib.sha256((ROOT / path).read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    assert manifest["files"][path] == digest
    subject.verify_manifest(ROOT, manifest)
    assert {"version": 288, "name": "file_audit_service_filter", "sha256": digest} in subject.expected_ledger(ROOT)


def test_inventory_uses_canonical_duplicate_and_marker_guards(source):
    migration = source / "config/postgres_migrations/002_duplicate.sql"
    migration.write_text("INSERT INTO schema_migrations(version,name) VALUES (2,'duplicate');", encoding="utf-8")
    with pytest.raises(RuntimeError, match="migration_version_duplicate"):
        subject.expected_ledger(source)


def docker_ledger():
    rows = []
    for line in (ROOT / "tests/fixtures/native_docker_ledger.txt").read_text().splitlines():
        version, name, checksum = line.split("|")
        rows.append({"version": int(version), "name": name, "sha256": checksum})
    return rows


def stand_expected():
    """Release ledger up to the stand's version: newer migrations apply natively first."""
    rows = docker_ledger()
    return [row for row in subject.expected_ledger(ROOT) if row["version"] <= rows[-1]["version"]]


def test_native_adopts_complete_docker_ledger_without_rewriting():
    rows = docker_ledger()
    original = copy.deepcopy(rows)
    expected = stand_expected()
    subject.verify_ledger(rows, expected, root=ROOT)
    assert rows == original
    assert len(rows) == 278 and rows[-1]["version"] == 285


def test_native_adoption_rejects_unknown_hash_at_every_version():
    rows = docker_ledger()
    expected = stand_expected()
    for row in rows:
        original = row["sha256"]
        row["sha256"] = "0" * 64
        with pytest.raises(ValueError, match="native_pg_ledger_mismatch_checksum"):
            subject.verify_ledger(rows, expected, root=ROOT)
        row["sha256"] = original


@pytest.mark.parametrize("change", ["null", "name", "missing", "extra", "duplicate", "order", "bool"])
def test_native_adoption_rejects_incomplete_or_foreign_docker_ledger(change):
    rows = docker_ledger()
    if change == "null":
        rows[0]["sha256"] = None
    elif change == "name":
        rows[0]["name"] = "foreign"
    elif change == "missing":
        rows.pop()
    elif change == "extra":
        rows.append({"version": 286, "name": "foreign", "sha256": "0" * 64})
    elif change == "duplicate":
        rows.append(rows[0])
    elif change == "order":
        rows.reverse()
    else:
        rows[0]["version"] = True
    with pytest.raises(ValueError, match="native_pg_ledger_mismatch"):
        subject.verify_ledger(rows, stand_expected(), root=ROOT)


@pytest.mark.parametrize("change", ["missing", "edit"])
def test_newline_adoption_requires_the_exact_release_source(source, change):
    expected = subject.expected_ledger(source)
    rows = copy.deepcopy(expected)
    schema = source / "config/postgres_schema_v8.sql"
    rows[0]["sha256"] = hashlib.sha256(schema.read_bytes().replace(b"\n", b"\r\n")).hexdigest()
    if change == "missing":
        schema.unlink()
    else:
        schema.write_bytes(schema.read_bytes() + b"-- a different revision\n")
    with pytest.raises(ValueError, match="native_pg_ledger_mismatch_(source|checksum)"):
        subject.verify_ledger(rows, expected, root=source)
