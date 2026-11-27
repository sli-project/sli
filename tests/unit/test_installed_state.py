"""Exact installed authority contracts, using synthetic inventory and fake DB."""
from __future__ import annotations

import copy
import hashlib
import json
from types import SimpleNamespace

import pytest

from deploy.linux import installed_state as state, migrate
from server.sli.release_package import PackageError


@pytest.fixture
def inventory():
    installed = {"version": "1.0.0", "image_tag": "synthetic:1", "image_digest": "sha256:" + "a" * 64,
                 "compose_project": "sli", "volumes": {"data": "synthetic-data"},
                 "build_id": "synthetic-build", "source_commit": "b" * 40,
                 "migrations": {"config/postgres_migrations/009_example.sql": "c" * 64},
                 "migration_ledger": [{"version": 1, "name": "initial", "sha256": "d" * 64},
                                      {"version": 9, "name": "example", "sha256": "c" * 64}],
                 "plugins": {"sli.fixture": {"version": "1.0.0", "migrations": {}}}}
    observed = {"migration_ledger_max": 9, "migration_ledger": copy.deepcopy(installed["migration_ledger"]),
                "services": {"api": {key: installed[key] for key in ("version", "image_tag", "image_digest")}},
                "plugins": [{"plugin_id": "sli.fixture", "version": "1.0.0", "installed": True, "enabled": False}],
                "installed_release": {"installation_key": state.installation_key(installed),
                                      "operation": "e" * 32, "inventory": state.inventory(installed)}}
    return installed, observed


@pytest.mark.parametrize("bad", ["hole", "name", "hash", "extra", "duplicate", "missing_hash", "bool_id"])
def test_same_max_different_exact_ledger_is_rejected(inventory, bad):
    installed, observed = inventory
    rows = observed["migration_ledger"]
    if bad == "hole":
        rows.pop(0)
    elif bad == "name":
        rows[-1]["name"] = "another_marker"
    elif bad == "hash":
        rows[-1]["sha256"] = "f" * 64
    elif bad == "extra":
        rows.insert(1, {"version": 2, "name": "unexpected", "sha256": "f" * 64})
    elif bad == "duplicate":
        rows.append(copy.deepcopy(rows[-1]))
    elif bad == "missing_hash":
        rows[-1]["sha256"] = None
    else:
        rows[0]["version"] = True
    with pytest.raises(PackageError, match="migration_ledger_mismatch"):
        state.validate(installed, observed)


def test_installed_hash_cannot_disagree_with_immutable_image_inventory(inventory):
    installed, observed = inventory
    installed["migrations"]["config/postgres_migrations/009_example.sql"] = "f" * 64
    with pytest.raises(PackageError, match="migration_ledger_mismatch"):
        state.ledger_matches(installed, observed)


@pytest.mark.parametrize("version", [9, 177, 178])
def test_legacy_adoption_keeps_source_hashes_distinct_from_db_attestation(inventory, version):
    installed, observed = inventory
    installed["migrations"] = {f"config/postgres_migrations/{version:03d}_example.sql": "c" * 64}
    installed["migration_ledger"][-1]["version"] = version
    observed["migration_ledger"] = copy.deepcopy(installed["migration_ledger"])
    observed["migration_ledger_max"] = version
    installed.update(ledger_source="deployed_image", adoption={"project": "sli"})
    observed.update(installed_release_available=False, installed_release=None)
    for row in observed["migration_ledger"]:
        row["sha256"] = None
    state.ledger_matches(installed, observed)
    observed["migration_ledger"][-1]["name"] = "foreign_marker"
    with pytest.raises(PackageError, match="migration_ledger_mismatch"):
        state.ledger_matches(installed, observed)
    observed["migration_ledger"] = copy.deepcopy(installed["migration_ledger"])
    observed["migration_ledger"][-1]["sha256"] = None
    observed["installed_release_available"] = True
    with pytest.raises(PackageError, match="migration_ledger_mismatch"):
        state.ledger_matches(installed, observed)


def test_installed_release_migration_requires_database_hash_attestation(inventory):
    installed, observed = inventory
    installed["migrations"] = {"config/postgres_migrations/179_installed_release.sql": "c" * 64}
    installed["migration_ledger"][-1].update(version=179, name="installed_release")
    installed.update(ledger_source="deployed_image", adoption={"project": "sli"})
    observed.update(migration_ledger_max=179, installed_release_available=False, installed_release=None,
                    migration_ledger=copy.deepcopy(installed["migration_ledger"]))
    observed["migration_ledger"][-1]["sha256"] = None
    with pytest.raises(PackageError, match="migration_ledger_mismatch"):
        state.ledger_matches(installed, observed)


@pytest.mark.parametrize("bad", ["foreign", "build", "digest", "plugin", "untracked_plugin"])
def test_registry_and_observation_are_independent_axes(inventory, bad):
    installed, observed = inventory
    if bad == "foreign":
        observed["installed_release"]["installation_key"] = "f" * 64
    elif bad == "build":
        observed["installed_release"]["inventory"]["build_id"] = "another-build"
    elif bad == "digest":
        observed["services"]["api"]["image_digest"] = "sha256:" + "f" * 64
    elif bad == "plugin":
        observed["plugins"][0]["version"] = "2.0.0"
    else:
        observed["plugins"].append({"plugin_id": "sli.untracked", "version": "1.0.0", "installed": True})
    with pytest.raises(PackageError):
        state.validate(installed, observed)


def test_enabled_and_readiness_do_not_rewrite_installed_inventory(inventory, tmp_path):
    installed, observed = inventory
    original = copy.deepcopy(installed)
    for enabled in (False, True):
        observed["plugins"][0]["enabled"] = enabled
        observed["plugins"][0]["receiving_data"] = enabled
        observed["plugins"][0]["configured"] = enabled
        state.validate(installed, observed, tmp_path)
    assert installed == original
    assert len(state.ledger_matches(installed, observed)["sha256"]) == 64


def test_untracked_pointer_is_rejected_for_bundled_plugin(inventory, tmp_path):
    from deploy.linux.sli_update import atomic_json
    installed, observed = inventory
    atomic_json(tmp_path / "plugins/sli.fixture/active.json", {"generation": "f" * 64})
    with pytest.raises(PackageError, match="plugin_pointer_mismatch"):
        state.validate(installed, observed, tmp_path)


@pytest.mark.parametrize(("case", "reason"), [
    ("bundled", None),
    ("selected", None),
    ("duplicate-pointer", "invalid JSON document"),
    ("wrong-version", "update_plugin_pointer_mismatch"),
    ("changed-asset", "update_plugin_payload_changed"),
    ("ui-contract", "plugin_ui_unsupported_api"),
    ("handler-rights", "handler_not_allowlisted"),
])
def test_native_pointer_decisions_match_updater(tmp_path, case, reason):
    plugin_id = "sli.remote-access"
    generation = "a" * 64
    plugin = tmp_path / "plugins" / plugin_id
    release = plugin / "versions" / generation
    current = {"version": "1.0.0", "generation": generation if case != "bundled" else None}
    installed = {"plugins": {plugin_id: current}}
    if case != "bundled":
        (release / "backend").mkdir(parents=True)
        (release / "ui").mkdir()
        jobs = json.loads((state.ROOT / "config/plugin_packages/sli.remote-access.jobs-v3.json").read_text("utf-8"))
        asset = b"export const version = '1.0.0';"
        descriptor = {"plugin_id": plugin_id, "version": "1.0.0", "ui_api": "sli.plugin-ui.v1",
                      "routes": [f"/extensions/{plugin_id}/accounts"], "required_capabilities": [],
                      "entry": {"path": "entry.js", "sha256": hashlib.sha256(asset).hexdigest()}}
        if case == "ui-contract":
            descriptor["ui_api"] = "sli.plugin-ui.invalid"
        if case == "handler-rights":
            jobs["handlers"][0]["resource_profile"] = "heavy"
        files = {"ui/descriptor.json": json.dumps(descriptor).encode(), "ui/entry.js": asset,
                 "backend/jobs-v3.json": json.dumps(jobs).encode()}
        for name, body in files.items():
            (release / name).write_bytes(body)
        manifest = {"plugin_id": plugin_id, "plugin_version": "2.0.0" if case == "wrong-version" else "1.0.0",
                    "files": [{"path": name, "size": len(body), "sha256": hashlib.sha256(body).hexdigest()}
                              for name, body in files.items()],
                    "core_api": jobs["core_api"], "handlers": [row["handler_id"] for row in jobs["handlers"]]}
        (release / "release.json").write_text(json.dumps(manifest), encoding="utf-8")
        pointer = json.dumps({"generation": generation})
        if case == "duplicate-pointer":
            pointer = f'{{"generation":"{generation}","generation":"{generation}"}}'
        (plugin / "active.json").write_text(pointer, encoding="utf-8")
        if case == "changed-asset":
            (release / "ui/entry.js").write_bytes(b"x" * len(asset))
    for check in (state.pointers_match, state.native_pointers_match):
        if reason:
            with pytest.raises(ValueError, match=reason):
                check(tmp_path, installed)
        else:
            assert check(tmp_path, installed) is None


@pytest.mark.parametrize("bad", [None, "checksum", "migration_checksum", "name", "hole"])
def test_migrator_attests_only_exact_source_ledger(monkeypatch, tmp_path, bad):
    root = tmp_path / "image"
    (root / "config").mkdir(parents=True)
    (root / "config/postgres_schema_v8.sql").write_bytes(b"synthetic-schema")
    monkeypatch.setattr(migrate, "ROOT", root)
    monkeypatch.setattr(migrate, "base_schema_markers", lambda _: [(1, "initial")])
    schema_hash = hashlib.sha256(b"synthetic-schema").hexdigest()
    migration = root / "config/009_example.sql"
    migration.write_bytes(b"synthetic-migration")
    migration_hash = hashlib.sha256(migration.read_bytes()).hexdigest()
    migrations = [SimpleNamespace(version=9, name="example", path=migration, sha256=migration_hash)]
    rows = [(1, "initial", schema_hash), (9, "example", None)]
    if bad == "checksum":
        rows[0] = (1, "initial", "b" * 64)
    elif bad == "migration_checksum":
        rows[-1] = (9, "example", "b" * 64)
    elif bad == "name":
        rows[-1] = (9, "foreign", None)
    elif bad == "hole":
        rows.pop(0)
    calls = []
    class Connection:
        def transaction(self):
            from contextlib import nullcontext
            return nullcontext()

        def execute(self, statement, params=None):
            calls.append((statement, params))
            return SimpleNamespace(fetchall=lambda: rows)

    if bad:
        with pytest.raises(RuntimeError, match="linux_migration_.*mismatch"):
            migrate.attest_ledger(Connection(), migrations, {1: "initial", 9: "example"}, write=True)
        assert all(params is None for _, params in calls)
    else:
        migrate.attest_ledger(Connection(), migrations, {1: "initial", 9: "example"}, write=True)
        assert [params for _, params in calls if params] == [(migration_hash, 9)]


@pytest.mark.parametrize("file_newline", [b"\n", b"\r\n"])
@pytest.mark.parametrize("ledger_newline", [b"\n", b"\r\n"])
def test_migrator_accepts_exact_newline_variants_without_rewriting(monkeypatch, tmp_path, file_newline, ledger_newline):
    from contextlib import nullcontext

    (tmp_path / "config").mkdir()
    schema = tmp_path / "config/postgres_schema_v8.sql"
    migration = tmp_path / "config/009_example.sql"
    schema.write_bytes(b"schema" + file_newline + b"body" + file_newline)
    migration.write_bytes(b"migration" + file_newline + b"body" + file_newline)
    original = (schema.read_bytes(), migration.read_bytes())
    monkeypatch.setattr(migrate, "ROOT", tmp_path)
    monkeypatch.setattr(migrate, "base_schema_markers", lambda _: [(1, "initial")])
    rows = [(1, "initial", hashlib.sha256(b"schema" + ledger_newline + b"body" + ledger_newline).hexdigest()),
            (9, "example", hashlib.sha256(b"migration" + ledger_newline + b"body" + ledger_newline).hexdigest())]
    original_rows = copy.deepcopy(rows)
    calls = []

    def execute(statement, params=None):
        calls.append((statement, params))
        return SimpleNamespace(fetchall=lambda: rows)

    connection = SimpleNamespace(execute=execute, transaction=nullcontext)
    migrations = [SimpleNamespace(version=9, name="example", path=migration,
                                  sha256=hashlib.sha256(migration.read_bytes()).hexdigest())]
    migrate.attest_ledger(connection, migrations, {1: "initial", 9: "example"}, write=True)
    assert len(calls) == 1 and calls[0][0].startswith("select ")
    assert rows == original_rows
    assert (schema.read_bytes(), migration.read_bytes()) == original


@pytest.mark.parametrize("file_newline", [b"\n", b"\r\n"])
@pytest.mark.parametrize("ledger_newline", [b"\n", b"\r\n"])
def test_installed_ledger_preserves_historical_newline_hash(inventory, monkeypatch, tmp_path, file_newline, ledger_newline):
    installed, observed = inventory
    path = "config/postgres_migrations/009_example.sql"
    source = tmp_path / path
    source.parent.mkdir(parents=True)
    source.write_bytes(b"select 1;" + file_newline + b"select 2;" + file_newline)
    monkeypatch.setattr(state, "ROOT", tmp_path)
    installed["migrations"][path] = hashlib.sha256(source.read_bytes()).hexdigest()
    historical_hash = hashlib.sha256(b"select 1;" + ledger_newline + b"select 2;" + ledger_newline).hexdigest()
    installed["migration_ledger"][-1]["sha256"] = historical_hash
    observed["migration_ledger"] = copy.deepcopy(installed["migration_ledger"])
    before = copy.deepcopy((installed, observed))
    state.ledger_matches(installed, observed)
    assert (installed, observed) == before


@pytest.mark.parametrize("body", [b"select 3;\nselect 2;\n", b"select 1; \nselect 2;\n",
                                   b"\xef\xbb\xbfselect 1;\nselect 2;\n", b"select 1;\rselect 2;\r",
                                   b"select 1;\r\nselect 2;\n"])
def test_only_two_newline_hashes_are_admitted(inventory, monkeypatch, tmp_path, body):
    installed, observed = inventory
    path = "config/postgres_migrations/009_example.sql"
    source = tmp_path / path
    source.parent.mkdir(parents=True)
    source.write_bytes(b"select 1;\nselect 2;\n")
    monkeypatch.setattr(state, "ROOT", tmp_path)
    installed["migrations"][path] = hashlib.sha256(source.read_bytes()).hexdigest()
    installed["migration_ledger"][-1]["sha256"] = hashlib.sha256(body).hexdigest()
    observed["migration_ledger"] = copy.deepcopy(installed["migration_ledger"])
    with pytest.raises(PackageError, match="migration_ledger_mismatch"):
        state.ledger_matches(installed, observed)


def test_newline_equivalence_requires_inventory_pinned_source(inventory, monkeypatch, tmp_path):
    installed, observed = inventory
    monkeypatch.setattr(state, "ROOT", tmp_path)
    installed["migration_ledger"][-1]["sha256"] = hashlib.sha256(b"select 1;\r\n").hexdigest()
    observed["migration_ledger"] = copy.deepcopy(installed["migration_ledger"])
    source = tmp_path / "config/postgres_migrations/009_example.sql"
    for available in (False, True):
        if available:
            source.parent.mkdir(parents=True)
            source.write_bytes(b"select 1;\n")
        with pytest.raises(PackageError, match="migration_ledger_mismatch"):
            state.ledger_matches(installed, observed)
