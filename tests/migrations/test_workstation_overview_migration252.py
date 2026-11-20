"""WR02 schema/update contracts with fakes, never an installed database."""

from __future__ import annotations

from contextlib import nullcontext
import copy
import hashlib
import json
from pathlib import Path
import re
import sys
from types import SimpleNamespace

import pytest

from deploy.linux import migrate
from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from server.sli.plugins.workstations import schema_contract as contract

ROOT = Path(__file__).resolve().parents[2]
PATH = contract.MIGRATION
SQL = PATH.read_text("utf-8")


def test_migration_is_unique_attested_and_requires_actual_main_predecessor():
    inventory = forward_migration_inventory(PATH.parent)
    pairs = [(row.version, row.name) for row in inventory]
    assert pairs[pairs.index((252, contract.NAME)) - 1] == (251, "workstation_access")
    assert len(pairs) == len({version for version, _ in pairs})
    assert list(PATH.parent.glob("252_*.sql")) == [PATH]
    assert "version=251 and name='workstation_access'" in SQL
    assert "version=209 and name='workstation_protection_state'" in SQL
    assert "version>=252" in SQL
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in SQL
    assert "pg_advisory_xact_lock" in SQL
    assert "set local role adlog_storage_owner" in SQL
    assert SQL.splitlines()[1] == "begin;" and SQL.strip().endswith("commit;")
    manifest = json.loads((ROOT / "config/plugin_packages/v3/sli.workstations.json").read_text("utf-8"))
    entry = next(row for row in manifest["data"]["migrations"] if row["version"] == 252)
    assert entry == {"version": 252, "name": contract.NAME, "path": str(PATH.relative_to(ROOT)).replace("\\", "/"),
                     "sha256": hashlib.sha256(PATH.read_bytes()).hexdigest(), "core_prerequisites": [251]}


def table_body(table):
    return SQL.split(f"create table {contract.SCHEMA}.{table} (", 1)[1].split("\n);", 1)[0]


def test_schema_report_covers_every_created_column_and_index():
    assert set(re.findall(r"create table sli_plugin_workstations\.(\w+)", SQL)) == set(contract.TABLE_COLUMNS)
    for table, expected in contract.TABLE_COLUMNS.items():
        columns = set(re.findall(r"^    (\w+) (?:text|bigint|integer|jsonb|timestamptz)\b", table_body(table), re.M))
        assert columns == expected
    created = set(re.findall(r"create index (\w+)", SQL))
    expected = {name for indexes in contract.TABLE_INDEXES.values() for name in indexes
                if name.startswith("workstation_")}
    assert created | {"workstation_finding_episode"} == expected
    assert "constraint workstation_finding_episode unique nulls not distinct" in SQL


def test_identity_episodes_unknowns_and_bounded_evidence_are_preserved():
    inventory = table_body("station_inventory")
    assert "station_id text primary key" in inventory
    for field in ("entity_id", "ad_computer_id", "agent_key"):
        assert re.search(rf"{field} (?:bigint|text) unique", inventory)
    assert "entity_id is not null or ad_computer_id is not null or agent_key is not null" in inventory
    assert "association_status<>'ambiguous' or (ad_computer_id is null and domain_id is null and ou_entity_id is null)" in inventory
    findings = table_body("check_findings")
    assert re.findall(r"'C\d\d'", findings) == [f"'C{number:02}'" for number in range(1, 11)]
    assert "unique nulls not distinct(check_id,rule_version,station_id,subject_id,episode_id)" in findings
    assert "resolved_at is not null and resolved_at>=first_detected_at" in findings
    assert "materially_changed_at>=first_detected_at" in findings
    for field in ("fact_at", "first_detected_at", "last_observed_at", "materially_changed_at"):
        assert field + " timestamptz" in findings
    for table in ("station_inventory", "station_summary", "check_findings", "station_changes"):
        assert "default '{\"status\":\"not_collected\",\"reasons\":[]}'" in table_body(table)
        assert "coalesce(quality->>'status' in" in table_body(table)
    assert "counters jsonb not null default '{}'" in table_body("station_summary")
    for table in ("check_findings", "station_changes"):
        body = table_body(table)
        assert "jsonb_typeof(evidence_refs)='array'" in body and "octet_length(evidence_refs::text)<=65536" in body
    assert "actor_ref jsonb" in table_body("station_changes")
    assert "committed_position jsonb" in table_body("projection_checkpoints")
    assert "primary key(projector_key,partition_key)" in table_body("projection_checkpoints")
    assert "source_xml" not in SQL
    assert "references sli_plugin_workstations.observations" not in SQL


def test_grants_are_projection_only_and_changes_are_append_only_for_runtime():
    grants = SQL[SQL.index("revoke all on"):SQL.index("reset role;")]
    assert "from public,adlog_user" in grants
    assert "grant select,insert on sli_plugin_workstations.station_changes to adlog_user" in grants
    writable = grants.split("grant select,insert,update on ", 1)[1].split(" to adlog_user;", 1)[0]
    assert set(re.findall(r"sli_plugin_workstations\.(\w+)", writable)) == set(contract.TABLE_COLUMNS) - {"station_changes"}
    assert "grant delete" not in SQL and "grant all" not in SQL
    assert "cascade" not in SQL.lower() and "alter table" not in SQL.lower()
    assert "insert into public.report" not in SQL and "access_package" not in SQL
    assert re.findall(r"insert into ([\w.]+)", SQL) == ["public.schema_migrations"]


class CatalogCursor:
    def __init__(self):
        self.marker = {"name": contract.NAME, "sha256": hashlib.sha256(PATH.read_bytes()).hexdigest()}
        self.schema = {"usage": True, "create_allowed": False}
        self.tables = [{"table_name": table, "owner": "adlog_storage_owner", "runtime_is_owner": False,
                        "public_access": False, "columns": sorted(columns)}
                       for table, columns in contract.TABLE_COLUMNS.items()]
        self.indexes = [{"table_name": table, "index_name": name, "indisvalid": True, "indisready": True}
                        for table, names in contract.TABLE_INDEXES.items() for name in names]
        self.grants = [{"table_name": table, "privilege": privilege,
                        "allowed": privilege in ({"SELECT", "INSERT"} if table == "station_changes"
                                                 else {"SELECT", "INSERT", "UPDATE"})}
                       for table in contract.TABLE_COLUMNS for privilege in contract.PRIVILEGES]
        self.calls = []

    def execute(self, sql, params=None):
        self.calls.append((sql, params))
        assert sql.lstrip().lower().startswith(("select ", "set "))
        if "from public.schema_migrations" in sql:
            assert params == (252,)
            self.result = self.marker
        elif "has_schema_privilege" in sql:
            self.result = self.schema
        elif "pg_attribute" in sql:
            assert "'MEMBER'" in sql
            self.result = self.tables
        elif "pg_index" in sql:
            self.result = self.indexes
        elif "has_table_privilege" in sql:
            # Each privilege is checked independently, never ANY-of privileges.
            assert params[0] == list(contract.PRIVILEGES)
            self.result = self.grants
        else:
            assert sql.startswith("set ")

    def fetchone(self):
        return self.result

    def fetchall(self):
        return self.result


def test_schema_contract_is_read_only_and_lists_objects_and_exact_effective_rights():
    cur = CatalogCursor()
    conn = SimpleNamespace(cursor=lambda: nullcontext(cur))
    original = copy.deepcopy((cur.marker, cur.tables, cur.indexes, cur.grants))
    first = contract.run(connect_factory=lambda: nullcontext(conn))
    assert first == contract.run(connect_factory=lambda: nullcontext(conn))
    assert first["status"] == "verified"
    assert all(row["verified"] for row in first["objects"])
    changes = next(row for row in first["objects"] if row["table"].endswith(".station_changes"))
    assert {key for key, allowed in changes["runtime_rights"].items() if allowed} == {"SELECT", "INSERT"}
    assert cur.calls[0][0] == "set transaction read only"
    assert (cur.marker, cur.tables, cur.indexes, cur.grants) == original


@pytest.mark.parametrize("defect", ["marker", "checksum", "unattested", "schema_usage", "schema_create",
                                     "table", "owner", "owner_member", "public", "column", "index",
                                     "invalid_index", "grant", "changes_update", "delete"])
def test_schema_contract_fails_closed_on_catalog_or_privilege_drift(defect):
    cur = CatalogCursor()
    if defect == "marker":
        cur.marker = None
    elif defect in ("checksum", "unattested"):
        cur.marker["sha256"] = "a" * 64 if defect == "checksum" else None
    elif defect == "schema_usage":
        cur.schema["usage"] = False
    elif defect == "schema_create":
        cur.schema["create_allowed"] = True
    elif defect == "table":
        cur.tables.pop()
    elif defect == "owner":
        cur.tables[0]["owner"] = "adlog_user"
    elif defect == "owner_member":
        cur.tables[0]["runtime_is_owner"] = True
    elif defect == "public":
        cur.tables[0]["public_access"] = True
    elif defect == "column":
        cur.tables[0]["columns"].remove("quality")
    elif defect == "index":
        cur.indexes.pop()
    elif defect == "invalid_index":
        cur.indexes[0]["indisvalid"] = False
    else:
        table, privilege = {"grant": ("station_inventory", "SELECT"),
                            "changes_update": ("station_changes", "UPDATE"),
                            "delete": ("check_findings", "DELETE")}[defect]
        row = next(row for row in cur.grants if row["table_name"] == table and row["privilege"] == privilege)
        row["allowed"] = not row["allowed"]
    assert contract.inspect_schema(cur, PATH.read_bytes())["status"] == "failed"


def test_contract_accepts_historical_crlf_checksum_without_rewriting_it():
    cur = CatalogCursor()
    cur.marker["sha256"] = hashlib.sha256(PATH.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")).hexdigest()
    original = dict(cur.marker)
    assert contract.inspect_schema(cur, PATH.read_bytes())["status"] == "verified"
    assert cur.marker == original


@pytest.mark.parametrize("argument,exit_code", [("--help", 0), ("-h", 0), ("--unknown-option", 2)])
def test_schema_contract_cli_parses_arguments_before_inspecting_database(argument, exit_code, monkeypatch, capsys):
    def unexpected_inspection():
        pytest.fail("CLI help and invalid arguments must not inspect the database")

    monkeypatch.setattr(contract, "run", unexpected_inspection)
    monkeypatch.setattr(sys, "argv", ["schema_contract", argument])
    with pytest.raises(SystemExit) as exc:
        contract.main()
    assert exc.value.code == exit_code
    captured = capsys.readouterr()
    assert "usage:" in (captured.out if exit_code == 0 else captured.err)
    assert "workstation_schema_contract_unavailable" not in captured.out


def test_schema_contract_cli_has_machine_status_and_redacts_connection_errors(monkeypatch, capsys):
    monkeypatch.setattr(contract, "run", lambda: {"status": "verified"})
    assert contract.main([]) == 0
    assert json.loads(capsys.readouterr().out) == {"status": "verified"}

    def unavailable():
        raise RuntimeError("synthetic-private-detail")

    monkeypatch.setattr(contract, "run", unavailable)
    assert contract.main([]) == 1
    assert json.loads(capsys.readouterr().out) == {"status": "failed", "code": "workstation_schema_contract_unavailable"}


def test_normal_update_replay_preserves_migration_checksum_and_projection_data():
    # This historical update fixture ends at WR02, before later migrations.
    migrations = tuple(row for row in forward_migration_inventory(PATH.parent) if row.version <= contract.VERSION)
    expected = dict(migrate.base_schema_markers(ROOT / "config/postgres_schema_v8.sql"))
    expected.update((row.version, row.name) for row in migrations)
    schema_hash = hashlib.sha256((ROOT / "config/postgres_schema_v8.sql").read_bytes()).hexdigest()
    hashes = {version: schema_hash for version, _ in migrate.base_schema_markers(ROOT / "config/postgres_schema_v8.sql")}
    hashes.update((row.version, row.sha256) for row in migrations)
    # Start before WR02 with a contiguous ledger and the whole later tail pending.
    ledger = {version: (name, hashes[version]) for version, name in expected.items() if version < 252}
    pending = [row for row in migrations if row.version >= 252]
    expected_calls = [[row.path] for row in pending]
    assert expected_calls[0] == [PATH]
    projection_rows = []
    calls = []

    def query(sql, params=None):
        if "update public.schema_migrations" in sql:
            checksum, version = params
            ledger[version] = (ledger[version][0], checksum)
        elif "where version = %s" in sql:
            return SimpleNamespace(fetchone=lambda: (ledger[params[0]][0],))
        elif "to_jsonb" in sql:
            return SimpleNamespace(fetchall=lambda: [(version, *value) for version, value in sorted(ledger.items())])
        else:
            return SimpleNamespace(fetchall=lambda: [(version, value[0]) for version, value in sorted(ledger.items())])

    def execute(paths):
        migration = pending[len(calls)]
        assert paths == [migration.path]
        calls.append(paths)
        ledger[migration.version] = (migration.name, None)
        # Applying storage creates no fabricated findings or inventory rows.
        assert not projection_rows

    connection = SimpleNamespace(execute=query, transaction=nullcontext)
    migrate.apply_pending(connection, migrations, expected, execute, baseline_version=251)
    migrate.attest_ledger(connection, migrations, expected, write=True)
    assert calls == expected_calls
    assert all(ledger[row.version] == (row.name, hashes[row.version]) for row in pending)
    projection_rows.append({"station_id": "synthetic-station", "revision": 2})
    before = copy.deepcopy((ledger, projection_rows))
    migrate.apply_pending(connection, migrations, expected, execute, baseline_version=251)
    migrate.attest_ledger(connection, migrations, expected, write=True)
    assert calls == expected_calls
    assert (ledger, projection_rows) == before
