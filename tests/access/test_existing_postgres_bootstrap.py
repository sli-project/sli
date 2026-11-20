from __future__ import annotations

import importlib
import io
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlunparse

import pytest

from deploy.linux.native_pg_inventory import expected_ledger, verify_manifest
from tests.migrations.migration_inventory import (
    MIGRATIONS_DIR, REVERSIBLE_CHAIN_START, migration_inventory,
)

ROOT = Path(__file__).resolve().parents[2]


def _bootstrap_module():
    try:
        return importlib.import_module(
            "scripts.maintenance.existing_postgres_bootstrap"
        )
    except ImportError as exc:
        pytest.fail(f"existing PostgreSQL bootstrap is unavailable: {exc}")


def test_forward_inventory_uses_real_files_and_ignores_both_rollback_forms(
    tmp_path: Path,
) -> None:
    """Catches applying rollback SQL or inventing numeric gap migrations."""
    root = tmp_path / "migrations"
    root.mkdir()
    (root / "009_storage.sql").write_text(
        "insert into schema_migrations(version, name) "
        "values (9, 'storage');\n",
        encoding="utf-8",
    )
    (root / "011_reports.sql").write_text(
        "insert into public.schema_migrations(version,name) "
        "values(11,'reports');\n",
        encoding="utf-8",
    )
    (root / "009_storage.rollback.sql").write_text("rollback;\n", encoding="utf-8")
    (root / "011_reports_rollback.sql").write_text("rollback;\n", encoding="utf-8")
    (root / "README.md").write_text("not a migration\n", encoding="utf-8")

    module = _bootstrap_module()
    inventory = module.forward_migration_inventory(root)

    assert [(item.version, item.name, item.path.name) for item in inventory] == [
        (9, "storage", "009_storage.sql"),
        (11, "reports", "011_reports.sql"),
    ]


def test_project_forward_inventory_matches_directory() -> None:
    inventory = _bootstrap_module().forward_migration_inventory(MIGRATIONS_DIR)
    assert [(item.version, item.path.name) for item in inventory] == [
        (version, f"{version:03}_{name}.sql") for version, name in migration_inventory()
    ]
    versions = [item.version for item in inventory]
    assert versions == sorted(set(versions)), "migration numbers must be unique and ascending"


def test_directory_inventory_sorts_numbers_and_ignores_rollback_files(tmp_path: Path) -> None:
    for version, name in ((10, "second"), (9, "first")):
        for suffix in (".sql", ".rollback.sql", "_rollback.sql"):
            (tmp_path / f"{version:03}_{name}{suffix}").write_text("", encoding="utf-8")
    assert migration_inventory(tmp_path) == [(9, "first"), (10, "second")]
    assert migration_inventory(tmp_path, starting_at=10) == [(10, "second")]


def test_reversible_ledger_is_ordered_pinned_and_every_migration_has_rollback() -> None:
    inventory = [(row["version"], row["name"]) for row in expected_ledger(ROOT)
                 if row["version"] >= REVERSIBLE_CHAIN_START]
    assert inventory == migration_inventory(starting_at=REVERSIBLE_CHAIN_START)
    versions = [version for version, _ in inventory]
    assert versions, "reversible migration chain is missing"
    assert versions == sorted(set(versions)), "migration numbers must be unique and ascending"
    manifest = json.loads((ROOT / "deploy/linux/native_pg_ledger.json").read_text("utf-8"))
    verify_manifest(ROOT, manifest)
    for version, name in inventory:
        rollback = MIGRATIONS_DIR / f"{version:03}_{name}.rollback.sql"
        assert rollback.is_file(), f"Missing rollback for migration {version}: {rollback.name}"


def test_all_migration_files_are_pinned_with_correct_sha256() -> None:
    manifest = json.loads((ROOT / "deploy/linux/native_pg_ledger.json").read_text("utf-8"))
    verify_manifest(ROOT, manifest)


def test_plan_binds_exact_cluster_state_and_migration_hashes(tmp_path: Path) -> None:
    """Catches applying a stale plan to another cluster or source revision."""
    module = _bootstrap_module()
    sql = tmp_path / "009_storage.sql"
    sql.write_text(
        "insert into schema_migrations(version,name) values(9,'storage');\n",
        encoding="utf-8",
    )
    inventory = module.forward_migration_inventory(tmp_path)
    snapshot = module.ClusterSnapshot(
        server_version_num=180006,
        data_directory=Path("D:/pgdata"),
        server_address="127.0.0.1",
        server_port=55433,
        database_exists=False,
        runtime_role_exists=False,
    )

    plan = module.build_plan(
        database="sli_local",
        expected_data_directory=Path("D:/pgdata"),
        snapshot=snapshot,
        schema_sha256="1" * 64,
        roles_sha256="2" * 64,
        migrations=inventory,
    )

    assert plan["operation"] == "bootstrap_existing_postgresql_18"
    assert plan["database"] == "sli_local"
    assert plan["cluster"]["server_version_num"] == 180006
    assert plan["cluster"]["data_directory"] == str(Path("D:/pgdata"))
    assert plan["migrations"] == [
        {
            "version": 9,
            "name": "storage",
            "path": "009_storage.sql",
            "sha256": inventory[0].sha256,
        }
    ]
    assert "password" not in repr(plan).casefold()
    assert len(module.plan_confirmation(plan)) == 64


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"server_version_num": 170009}, "postgresql_18_required"),
        ({"server_address": "192.0.2.10"}, "loopback_required"),
        ({"server_port": 5432}, "cluster_identity_mismatch"),
        ({"data_directory": Path("D:/other")}, "cluster_identity_mismatch"),
        ({"database_exists": True}, "target_database_exists"),
        ({"runtime_role_exists": True}, "runtime_role_exists"),
    ],
)
def test_validate_new_target_rejects_cluster_or_existing_state(change, code) -> None:
    """Catches mutating an unexpected cluster or reusing an existing target."""
    module = _bootstrap_module()
    values = {
        "server_version_num": 180006,
        "data_directory": Path("D:/pgdata"),
        "server_address": "127.0.0.1",
        "server_port": 55433,
        "database_exists": False,
        "runtime_role_exists": False,
    }
    values.update(change)

    with pytest.raises(module.BootstrapError, match=f"^{code}$"):
        module.validate_new_target(
            module.ClusterSnapshot(**values),
            expected_data_directory=Path("D:/pgdata"),
            expected_port=55433,
        )


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "127.0.0.1/32",
        "::1",
        "::1/128",
        "::ffff:127.0.0.1",
        "::ffff:127.0.0.1/128",
    ],
)
def test_validate_new_target_accepts_equivalent_loopback_addresses(address) -> None:
    """Catches rejecting Windows IPv6 or IPv4-mapped loopback readback."""
    module = _bootstrap_module()

    module.validate_new_target(
        module.ClusterSnapshot(
            server_version_num=180006,
            data_directory=Path("D:/pgdata"),
            server_address=address,
            server_port=55433,
            database_exists=False,
            runtime_role_exists=False,
        ),
        expected_data_directory=Path("D:/pgdata"),
        expected_port=55433,
    )


def test_psql_file_keeps_password_out_of_command_and_captured_output(
    tmp_path: Path,
) -> None:
    """Catches credentials leaking through argv, stdin or returned evidence."""
    module = _bootstrap_module()
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout="migration output", stderr="")

    sql_path = tmp_path / "009_storage.sql"
    sql_path.write_text("select 1;\n", encoding="utf-8")
    result = module.run_psql_file(
        psql=Path("D:/PostgreSQL/18/bin/psql.exe"),
        host="127.0.0.1",
        port=55433,
        user="postgres",
        database="sli_local",
        sql_path=sql_path,
        password="synthetic-admin-secret",
        runner=runner,
        source={"SYSTEMROOT": "C:/Windows", "TEMP": str(tmp_path)},
    )

    command, kwargs = calls[0]
    # -X disables both system and user psqlrc before any connection-changing
    # startup command can escape the explicitly selected target cluster.
    assert command == [
        str(Path("D:/PostgreSQL/18/bin/psql.exe")), "-X",
        "--host", "127.0.0.1", "--port", "55433",
        "--username", "postgres", "--dbname", "sli_local",
        "--no-password", "--set", "ON_ERROR_STOP=1", "--file", str(sql_path),
    ]
    assert "synthetic-admin-secret" not in repr(command)
    assert kwargs["input"] is None
    assert kwargs["env"]["PGPASSWORD"] == "synthetic-admin-secret"
    assert "--no-password" in command
    assert "ON_ERROR_STOP=1" in command
    assert result == {"status": "ok"}


def test_exact_ledger_rejects_missing_extra_or_renamed_markers() -> None:
    """Catches treating a maximum migration version as schema completeness."""
    module = _bootstrap_module()
    expected = ((1, "base"), (9, "storage"), (11, "reports"))

    module.verify_exact_ledger(expected, expected)
    for actual in (
        ((1, "base"), (11, "reports")),
        ((1, "base"), (9, "wrong"), (11, "reports")),
        ((1, "base"), (9, "storage"), (10, "invented"), (11, "reports")),
    ):
        with pytest.raises(module.BootstrapError, match="^migration_ledger_mismatch$"):
            module.verify_exact_ledger(actual, expected)


def test_base_schema_inventory_reads_all_declared_markers() -> None:
    """Catches omitting a baseline marker before forward migrations."""
    module = _bootstrap_module()

    markers = module.base_schema_markers(ROOT / "config" / "postgres_schema.sql")

    assert markers == (
        (1, "initial_postgres_schema"),
        (2, "stage_4_1_persistent_findings"),
        (3, "stage_4_3_ai_api_prompt_runs"),
        (4, "stage_4_4_ai_report_pipeline"),
        (5, "db_0_1_postgres_readiness"),
        (6, "findings_pg1_incremental_pipeline"),
        (7, "storage_lifecycle2_measurement_and_backup_rehearsal"),
        (8, "ops_stability1_runtime_contracts"),
    )


def test_replay_baseline_contains_only_schema_versions_one_through_eight() -> None:
    """Catches replaying migrations over a current-state schema snapshot."""
    module = _bootstrap_module()
    baseline = ROOT / "config" / "postgres_schema_v8.sql"

    assert module.base_schema_markers(baseline) == tuple(
        (version, name)
        for version, name in module.base_schema_markers(
            ROOT / "config" / "postgres_schema.sql"
        )
        if version <= 8
    )
    sql = baseline.read_text(encoding="utf-8").casefold()
    assert "ad_snapshot_manifests" not in sql
    assert "raw_batch_lifecycle" not in sql


def test_controller_inventory_yields_one_configured_source_domain(
    tmp_path: Path,
) -> None:
    """Catches inventing a domain or accepting controllers from mixed domains."""
    module = _bootstrap_module()
    config = tmp_path / "domain_controllers.json"
    config.write_text(
        json.dumps(
            {
                "domain_controllers": [
                    {"connect_address": "DC1.example.test"},
                    {"connect_address": "dc2.example.test"},
                ]
            }
        ),
        encoding="utf-8",
    )

    assert module.configured_source_domain(config) == "example.test"

    config.write_text(
        json.dumps(
            {
                "domain_controllers": [
                    {"connect_address": "dc1.example.test"},
                    {"connect_address": "dc2.other.example"},
                ]
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(module.BootstrapError, match="^source_domain_ambiguous$"):
        module.configured_source_domain(config)


def test_source_domain_is_seeded_before_domain_bound_migrations() -> None:
    """Catches applying report migrations before their configured domain exists."""
    module = _bootstrap_module()
    calls = []

    class Cursor:
        def __init__(self, row):
            self._row = row

        def fetchone(self):
            return self._row

    def execute(statement, parameters=None):
        calls.append((statement, parameters))
        if "insert into public.forests" in statement.casefold():
            return Cursor((7,))
        if "insert into public.domains" in statement.casefold():
            return Cursor((11,))
        return Cursor((1,))

    module.seed_source_domain(execute, "example.test")

    assert calls[0][1] == ("example.test",)
    assert calls[1][1] == (7, "example.test")
    assert "example.test" not in calls[0][0].casefold()
    assert "example.test" not in calls[1][0].casefold()


def test_schema_sequence_uses_runtime_owner_then_admin_and_sets_empty_v2_route(
    tmp_path: Path,
) -> None:
    """Catches wrong legacy ownership or applying migration 12 before its gate."""
    module = _bootstrap_module()
    schema = tmp_path / "postgres_schema.sql"
    roles = tmp_path / "storage_v2_roles.sql"
    migrations_root = tmp_path / "migrations"
    migrations_root.mkdir()
    schema.write_text("select 1;\n", encoding="utf-8")
    roles.write_text("select 2;\n", encoding="utf-8")
    for version, name in (
        (9, "storage"),
        (11, "routing"),
        (12, "cutover"),
        (14, "auth"),
        (37, "owner"),
    ):
        elevated = (
            "set local role adlog_storage_owner; " if version in {9, 11, 12}
            else ""
        )
        (migrations_root / f"{version:03d}_{name}.sql").write_text(
            elevated + "insert into schema_migrations(version,name) "
            f"values({version},'{name}');\n",
            encoding="utf-8",
        )
    migrations = module.forward_migration_inventory(migrations_root)
    calls = []
    admin_calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    module.apply_schema_sequence(
        schema_path=schema,
        roles_path=roles,
        migrations=migrations,
        psql=Path("D:/PostgreSQL/18/bin/psql.exe"),
        host="127.0.0.1",
        port=55433,
        database="sli_local",
        admin_password="synthetic-admin",
        runtime_password="synthetic-runtime",
        platform_owner_password="synthetic-owner-password",
        admin_execute=lambda statement, parameters=None: admin_calls.append(
            (statement, parameters)
        ),
        runner=runner,
        source={"SYSTEMROOT": "C:/Windows", "TEMP": str(tmp_path)},
    )

    assert [Path(call[0][-1]).name for call in calls] == [
        schema.name, roles.name, *[item.path.name for item in migrations]
    ]
    assert [
        call[0][call[0].index("--username") + 1] for call in calls
    ] == [
        "adlog_user",
        "postgres",
        "postgres",
        "postgres",
        "postgres",
        "adlog_user",
        "adlog_user",
    ]
    assert admin_calls[0] == (module.PGCRYPTO_BOOTSTRAP_SQL, None)
    assert admin_calls[1] == (module.RUNTIME_SCHEMA_BOOTSTRAP_GRANT_SQL, None)
    assert admin_calls[2] == (module.EMPTY_DATABASE_V2_ROUTE_SQL, None)
    owner_sql, owner_parameters = admin_calls[3]
    assert "insert into public.auth_users" in owner_sql.casefold()
    assert owner_parameters[0] == "platform-owner"
    assert owner_parameters[2] == "admin"
    assert owner_parameters[1].startswith("$argon2id$")
    assert "synthetic-owner-password" not in owner_sql
    assert "synthetic-admin" not in repr([call[0] for call in calls])
    assert "synthetic-runtime" not in repr([call[0] for call in calls])


def test_schema_sequence_preserves_application_and_elevated_object_owners(
    tmp_path: Path,
) -> None:
    """Catches creating ordinary migration objects as postgres instead of adlog_user."""
    module = _bootstrap_module()
    schema = tmp_path / "postgres_schema.sql"
    roles = tmp_path / "storage_v2_roles.sql"
    migrations_root = tmp_path / "migrations"
    migrations_root.mkdir()
    schema.write_text("select 1;\n", encoding="utf-8")
    roles.write_text("select 2;\n", encoding="utf-8")
    (migrations_root / "017_application.sql").write_text(
        "create table application_owned(id bigint); "
        "insert into schema_migrations(version,name) values(17,'application');\n",
        encoding="utf-8",
    )
    (migrations_root / "019_elevated.sql").write_text(
        "select pg_has_role(session_user,'adlog_storage_owner','MEMBER'); "
        "set local role adlog_storage_owner; "
        "create table storage_owned(id bigint); "
        "insert into schema_migrations(version,name) values(19,'elevated');\n",
        encoding="utf-8",
    )
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    module.apply_schema_sequence(
        schema_path=schema,
        roles_path=roles,
        migrations=module.forward_migration_inventory(migrations_root),
        psql=Path("D:/PostgreSQL/18/bin/psql.exe"),
        host="127.0.0.1",
        port=55433,
        database="sli_local",
        admin_password="synthetic-admin",
        runtime_password="synthetic-runtime",
        platform_owner_password="synthetic-owner-password",
        admin_execute=lambda _statement, _parameters=None: None,
        runner=runner,
        source={"SYSTEMROOT": "C:/Windows", "TEMP": str(tmp_path)},
    )

    assert [
        call[0][call[0].index("--username") + 1] for call in calls
    ] == [
        "adlog_user",
        "postgres",
        "adlog_user",
        "postgres",
    ]


def test_schema_sequence_elevates_mixed_owner_casefold_migration(
    tmp_path: Path,
) -> None:
    """Catches running migration 020 as a role that cannot own both table sets."""
    module = _bootstrap_module()
    schema = tmp_path / "postgres_schema.sql"
    roles = tmp_path / "storage_v2_roles.sql"
    migrations_root = tmp_path / "migrations"
    migrations_root.mkdir()
    schema.write_text("select 1;\n", encoding="utf-8")
    roles.write_text("select 2;\n", encoding="utf-8")
    (migrations_root / "020_casefold_search_indexes.sql").write_text(
        "create index concurrently if not exists idx_app on events(id); "
        "create index concurrently if not exists idx_storage on events_v2_core(id); "
        "insert into schema_migrations(version,name) values(20,'casefold_search_indexes');\n",
        encoding="utf-8",
    )
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    module.apply_schema_sequence(
        schema_path=schema,
        roles_path=roles,
        migrations=module.forward_migration_inventory(migrations_root),
        psql=Path("D:/PostgreSQL/18/bin/psql.exe"),
        host="127.0.0.1",
        port=55433,
        database="sli_local",
        admin_password="synthetic-admin",
        runtime_password="synthetic-runtime",
        platform_owner_password="synthetic-owner-password",
        admin_execute=lambda _statement, _parameters=None: None,
        runner=runner,
        source={"SYSTEMROOT": "C:/Windows", "TEMP": str(tmp_path)},
    )

    assert calls[-1][0][calls[-1][0].index("--username") + 1] == "postgres"


def test_create_platform_owner_hashes_secret_and_rejects_short_password() -> None:
    """Catches storing a web-owner password in plaintext or accepting a weak one."""
    module = _bootstrap_module()

    class Connection:
        def __init__(self):
            self.calls = []

        def execute(self, statement, parameters=None):
            self.calls.append((statement, parameters))

    connection = Connection()
    module.create_platform_owner(connection, "synthetic-owner-password")

    statement, parameters = connection.calls[0]
    assert "synthetic-owner-password" not in statement
    assert parameters[0] == "platform-owner"
    assert parameters[2] == "admin"
    assert parameters[1].startswith("$argon2id$")
    from server.sli.access.auth import PASSWORD_HASHER

    assert PASSWORD_HASHER.verify(parameters[1], "synthetic-owner-password") is True
    with pytest.raises(module.BootstrapError, match="^platform_owner_password_invalid$"):
        module.create_platform_owner(connection, "too-short")


def test_create_target_parameterizes_secret_and_keeps_runtime_from_database_owner() -> None:
    """Catches secret interpolation or implicit schema authority via DB ownership."""
    module = _bootstrap_module()

    class Connection:
        def __init__(self):
            self.calls = []

        def execute(self, statement, parameters=None):
            self.calls.append((statement, parameters))

    connection = Connection()
    module.create_target_database(
        connection,
        database="sli_local",
        runtime_password="synthetic-runtime-secret",
    )

    text = "\n".join(statement for statement, _parameters in connection.calls)
    assert "synthetic-runtime-secret" not in text
    assert any(
        parameters == ("synthetic-runtime-secret",)
        for _statement, parameters in connection.calls
    )
    assert 'CREATE DATABASE "sli_local" OWNER "postgres"' in text
    assert 'OWNER "adlog_user"' not in text
    assert "NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS" in text


def test_hardened_migrations_revoke_runtime_schema_create_and_use_admin(
    tmp_path: Path,
) -> None:
    """Catches violating migration 089's trusted public-schema boundary."""
    module = _bootstrap_module()
    schema = tmp_path / "postgres_schema.sql"
    roles = tmp_path / "storage_v2_roles.sql"
    migrations_root = tmp_path / "migrations"
    migrations_root.mkdir()
    schema.write_text("select 1;\n", encoding="utf-8")
    roles.write_text("select 2;\n", encoding="utf-8")
    (migrations_root / "089_hardened.sql").write_text(
        "insert into schema_migrations(version,name) values(89,'hardened');\n",
        encoding="utf-8",
    )
    calls = []
    admin_calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    module.apply_schema_sequence(
        schema_path=schema,
        roles_path=roles,
        migrations=module.forward_migration_inventory(migrations_root),
        psql=Path("D:/PostgreSQL/18/bin/psql.exe"),
        host="127.0.0.1",
        port=55433,
        database="sli_local",
        admin_password="synthetic-admin",
        runtime_password="synthetic-runtime",
        platform_owner_password="synthetic-owner-password",
        admin_execute=lambda statement, parameters=None: admin_calls.append(
            (statement, parameters)
        ),
        runner=runner,
        source={"SYSTEMROOT": "C:/Windows", "TEMP": str(tmp_path)},
    )

    assert calls[-1][0][calls[-1][0].index("--username") + 1] == "postgres"
    assert admin_calls == [
        (module.PGCRYPTO_BOOTSTRAP_SQL, None),
        (module.RUNTIME_SCHEMA_BOOTSTRAP_GRANT_SQL, None),
        (module.RUNTIME_SCHEMA_CREATE_REVOKE_SQL, None),
    ]


def test_runtime_candidate_is_inactive_dpapi_and_contains_no_plaintext(
    tmp_path: Path,
) -> None:
    """Catches persisting the runtime DSN before explicit activation or in cleartext."""
    module = _bootstrap_module()
    protected_inputs = []

    def protector(value: str) -> str:
        protected_inputs.append(value)
        return "synthetic-dpapi-payload"

    path = module.write_runtime_candidate(
        profile_dir=tmp_path / "profile",
        database="sli_local",
        host="127.0.0.1",
        port=55433,
        runtime_password="synthetic-runtime-secret",
        identity_sid="S-1-5-21-1-2-3-1000",
        protector=protector,
    )

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert protected_inputs == [
        urlunparse(
            (
                "postgresql",
                "adlog_user:synthetic-runtime-secret@127.0.0.1:55433",
                "/sli_local",
                "",
                "",
                "",
            )
        )
    ]
    assert payload == {
        "active": False,
        "candidate_version": 1,
        "identity_sid": "S-1-5-21-1-2-3-1000",
        "kind": "runtime",
        "payload": "synthetic-dpapi-payload",
        "protection": "windows-dpapi-current-user",
        "role": "adlog_user",
    }
    assert "synthetic-runtime-secret" not in path.read_text(encoding="utf-8")


def test_runtime_candidate_accepts_an_existing_empty_private_directory(
    tmp_path: Path,
) -> None:
    """Catches writing the DPAPI payload before directory ACL hardening."""
    module = _bootstrap_module()
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir()

    path = module.write_runtime_candidate(
        profile_dir=profile_dir,
        database="sli_local",
        host="127.0.0.1",
        port=55433,
        runtime_password="synthetic-runtime-secret",
        identity_sid="S-1-5-21-1-2-3-1000",
        protector=lambda _value: "synthetic-dpapi-payload",
    )

    assert path.parent == profile_dir


def test_admin_password_round_trips_only_through_a_dpapi_envelope(
    tmp_path: Path,
) -> None:
    """Catches retaining the PostgreSQL administrator password as plaintext."""
    module = _bootstrap_module()
    path = tmp_path / "postgres-admin.dpapi.json"
    protected_inputs = []

    module.write_admin_credential(
        path=path,
        password="synthetic-admin-secret",
        identity_sid="S-1-5-21-1-2-3-1000",
        protector=lambda value: protected_inputs.append(value) or "sealed-payload",
    )

    serialized = path.read_text(encoding="utf-8")
    assert protected_inputs == ["synthetic-admin-secret"]
    assert "synthetic-admin-secret" not in serialized
    assert json.loads(serialized) == {
        "credential_version": 1,
        "identity_sid": "S-1-5-21-1-2-3-1000",
        "kind": "postgresql-administrator",
        "payload": "sealed-payload",
        "protection": "windows-dpapi-current-user",
        "purpose": "sli-existing-postgres-admin-v1",
        "role": "postgres",
    }
    assert module.read_admin_credential(
        path=path,
        identity_sid="S-1-5-21-1-2-3-1000",
        unprotector=lambda value: (
            "synthetic-admin-secret" if value == "sealed-payload" else "wrong"
        ),
    ) == "synthetic-admin-secret"


def test_admin_password_store_refuses_replace_or_wrong_windows_identity(
    tmp_path: Path,
) -> None:
    """Catches silent credential overwrite or decryption under another SID."""
    module = _bootstrap_module()
    path = tmp_path / "postgres-admin.dpapi.json"
    module.write_admin_credential(
        path=path,
        password="first-secret",
        identity_sid="S-1-5-21-1-2-3-1000",
        protector=lambda _value: "first-sealed",
    )

    with pytest.raises(module.BootstrapError, match="^admin_credential_exists$"):
        module.write_admin_credential(
            path=path,
            password="second-secret",
            identity_sid="S-1-5-21-1-2-3-1000",
            protector=lambda _value: "second-sealed",
        )
    with pytest.raises(module.BootstrapError, match="^admin_credential_owner_mismatch$"):
        module.read_admin_credential(
            path=path,
            identity_sid="S-1-5-21-9-9-9-1000",
            unprotector=lambda _value: "first-secret",
        )


def test_platform_owner_password_round_trips_only_through_dpapi(
    tmp_path: Path,
) -> None:
    """Catches persisting the new web-owner password as plaintext."""
    module = _bootstrap_module()
    path = tmp_path / "platform-owner.dpapi.json"

    module.write_platform_owner_credential(
        path=path,
        password="synthetic-owner-password",
        identity_sid="S-1-5-21-1-2-3-1000",
        protector=lambda _value: "owner-sealed-payload",
    )

    serialized = path.read_text(encoding="utf-8")
    assert "synthetic-owner-password" not in serialized
    assert json.loads(serialized) == {
        "credential_version": 1,
        "identity_sid": "S-1-5-21-1-2-3-1000",
        "kind": "sli-platform-owner",
        "payload": "owner-sealed-payload",
        "protection": "windows-dpapi-current-user",
        "purpose": "sli-platform-owner-password-v1",
        "role": "platform-owner",
    }
    assert module.read_platform_owner_credential(
        path=path,
        identity_sid="S-1-5-21-1-2-3-1000",
        unprotector=lambda _value: "synthetic-owner-password",
    ) == "synthetic-owner-password"


def test_apply_after_plan_persists_only_a_validated_admin_password(
    monkeypatch, capsys
) -> None:
    """Catches saving an unverified password or applying before DPAPI persistence."""
    module = _bootstrap_module()
    plan = {"operation": "bootstrap_existing_postgresql_18", "database": "sli_local"}
    events = []
    monkeypatch.setattr(
        module.sys,
        "stdin",
        io.StringIO("synthetic-admin\nsynthetic-owner-password\n"),
    )
    monkeypatch.setattr(
        module,
        "validate_admin_credentials",
        lambda _opts, password: events.append(("validated", password)) or plan,
    )
    monkeypatch.setattr(module, "prepare_live_plan", lambda _opts, _password: plan)
    monkeypatch.setattr(
        module,
        "save_admin_password",
        lambda app_root, password: events.append(("saved", app_root, password))
        or Path("D:/admin.dpapi.json"),
    )
    monkeypatch.setattr(
        module,
        "save_platform_owner_password",
        lambda app_root, password: events.append(("owner-saved", app_root, password))
        or Path("D:/owner.dpapi.json"),
    )
    monkeypatch.setattr(
        module,
        "perform_apply",
        lambda _opts, password, owner_password, _plan, _confirmation: events.append(
            ("applied", password, owner_password)
        )
        or Path("D:/receipt.json"),
    )

    code = module.main(
        [
            "--app-root",
            "D:/sli/app",
            "--bin-dir",
            "D:/PostgreSQL/18/bin",
            "--data-dir",
            "D:/pgdata",
            "--database",
            "sli_local",
            "--admin-password-stdin",
            "--save-admin-password",
            "--platform-owner-password-stdin",
            "--save-platform-owner-password",
            "--apply-after-plan",
        ]
    )

    output = capsys.readouterr()
    assert code == 0
    assert events == [
        ("validated", "synthetic-admin"),
        ("saved", Path("D:/sli/app"), "synthetic-admin"),
        (
            "owner-saved",
            Path("D:/sli/app"),
            "synthetic-owner-password",
        ),
        ("applied", "synthetic-admin", "synthetic-owner-password"),
    ]
    assert "synthetic-admin" not in output.out
    assert "synthetic-admin" not in output.err


def test_apply_after_plan_seals_credentials_before_plan_level_failure(
    monkeypatch, capsys
) -> None:
    """Catches forcing a second prompt after authenticated plan validation fails."""
    module = _bootstrap_module()
    events = []
    monkeypatch.setattr(
        module.sys,
        "stdin",
        io.StringIO("synthetic-admin\nsynthetic-owner-password\n"),
    )
    monkeypatch.setattr(
        module,
        "validate_admin_credentials",
        lambda _opts, password: events.append(("validated", password)),
    )
    monkeypatch.setattr(
        module,
        "save_admin_password",
        lambda app_root, password: events.append(("admin-saved", app_root, password)),
    )
    monkeypatch.setattr(
        module,
        "save_platform_owner_password",
        lambda app_root, password: events.append(("owner-saved", app_root, password)),
    )

    def fail(_opts, _password):
        raise module.BootstrapError("target_database_exists")

    monkeypatch.setattr(module, "prepare_live_plan", fail)

    code = module.main(
        [
            "--app-root",
            "D:/sli/app",
            "--bin-dir",
            "D:/PostgreSQL/18/bin",
            "--data-dir",
            "D:/pgdata",
            "--database",
            "sli_local",
            "--admin-password-stdin",
            "--save-admin-password",
            "--platform-owner-password-stdin",
            "--save-platform-owner-password",
            "--apply-after-plan",
        ]
    )

    output = capsys.readouterr()
    assert code == 2
    assert events == [
        ("validated", "synthetic-admin"),
        ("admin-saved", Path("D:/sli/app"), "synthetic-admin"),
        (
            "owner-saved",
            Path("D:/sli/app"),
            "synthetic-owner-password",
        ),
    ]
    assert json.loads(output.err) == {
        "code": "target_database_exists",
        "status": "error",
    }
    assert "synthetic-admin" not in output.err
    assert "synthetic-owner-password" not in output.err


def test_apply_after_plan_reuses_saved_admin_password_without_prompt(
    monkeypatch, capsys
) -> None:
    """Catches prompting again after the administrator secret was persisted."""
    module = _bootstrap_module()
    plan = {"operation": "bootstrap_existing_postgresql_18", "database": "sli_local"}
    seen = []
    monkeypatch.setattr(
        module.getpass,
        "getpass",
        lambda _prompt: pytest.fail("saved credential must avoid another prompt"),
    )
    monkeypatch.setattr(
        module,
        "load_saved_admin_password",
        lambda app_root: seen.append(("loaded", app_root)) or "synthetic-admin",
    )
    monkeypatch.setattr(
        module,
        "load_saved_platform_owner_password",
        lambda app_root: seen.append(("owner-loaded", app_root))
        or "synthetic-owner-password",
    )
    monkeypatch.setattr(
        module,
        "prepare_live_plan",
        lambda _opts, password: seen.append(("validated", password)) or plan,
    )
    monkeypatch.setattr(
        module,
        "perform_apply",
        lambda _opts, password, owner_password, _plan, _confirmation: seen.append(
            ("applied", password, owner_password)
        )
        or Path("D:/receipt.json"),
    )

    code = module.main(
        [
            "--app-root",
            "D:/sli/app",
            "--bin-dir",
            "D:/PostgreSQL/18/bin",
            "--data-dir",
            "D:/pgdata",
            "--database",
            "sli_local",
            "--use-saved-admin-password",
            "--use-saved-platform-owner-password",
            "--apply-after-plan",
        ]
    )

    output = capsys.readouterr()
    assert code == 0
    assert seen == [
        ("loaded", Path("D:/sli/app")),
        ("owner-loaded", Path("D:/sli/app")),
        ("validated", "synthetic-admin"),
        ("applied", "synthetic-admin", "synthetic-owner-password"),
    ]
    assert "synthetic-admin" not in output.out
    assert "synthetic-admin" not in output.err


def test_cluster_snapshot_reads_server_identity_and_target_absence() -> None:
    """Catches planning from client assumptions instead of server readback."""
    module = _bootstrap_module()

    class Result:
        def fetchone(self):
            return (
                180006,
                "D:/pgdata",
                "127.0.0.1",
                55433,
                False,
                False,
                "postgres",
                True,
            )

    class Connection:
        def execute(self, statement, parameters):
            assert "current_setting('server_version_num')" in statement
            assert parameters == ("sli_local", "adlog_user")
            return Result()

    snapshot = module.read_cluster_snapshot(Connection(), database="sli_local")

    assert snapshot == module.ClusterSnapshot(
        server_version_num=180006,
        data_directory=Path("D:/pgdata"),
        server_address="127.0.0.1",
        server_port=55433,
        database_exists=False,
        runtime_role_exists=False,
        current_user="postgres",
        admin_is_superuser=True,
    )


def test_main_plan_uses_hidden_password_and_prints_only_sanitized_envelope(
    monkeypatch, capsys
) -> None:
    """Catches accepting an admin password in argv or echoing it in plan output."""
    module = _bootstrap_module()
    seen = []
    plan = {"operation": "bootstrap_existing_postgresql_18", "database": "sli_local"}
    monkeypatch.setattr(
        module.getpass,
        "getpass",
        lambda prompt: (
            "synthetic-owner-password" if "platform-owner" in prompt
            else "synthetic-admin"
        ),
    )
    monkeypatch.setattr(
        module,
        "prepare_live_plan",
        lambda _opts, password: seen.append(password) or plan,
    )

    code = module.main(
        [
            "--app-root",
            "D:/sli/app",
            "--bin-dir",
            "D:/PostgreSQL/18/bin",
            "--data-dir",
            "D:/pgdata",
            "--database",
            "sli_local",
        ]
    )

    output = capsys.readouterr()
    assert code == 0
    assert seen == ["synthetic-admin"]
    assert output.err == ""
    assert "synthetic-admin" not in output.out
    assert json.loads(output.out) == {
        "confirmation_sha256": module.plan_confirmation(plan),
        "mode": "plan",
        "plan": plan,
    }


def test_main_apply_rechecks_hash_and_reports_only_receipt(monkeypatch, capsys) -> None:
    """Catches applying without the exact plan or returning credentials."""
    module = _bootstrap_module()
    plan = {"operation": "bootstrap_existing_postgresql_18", "database": "sli_local"}
    confirmation = module.plan_confirmation(plan)
    seen = []
    monkeypatch.setattr(
        module.getpass,
        "getpass",
        lambda prompt: (
            "synthetic-owner-password"
            if "platform-owner" in prompt
            else "synthetic-admin"
        ),
    )
    monkeypatch.setattr(module, "prepare_live_plan", lambda _opts, _password: plan)
    monkeypatch.setattr(
        module,
        "perform_apply",
        lambda _opts, password, owner_password, plan_value, confirmation_value: seen.append(
            (password, owner_password, plan_value, confirmation_value)
        )
        or Path("D:/receipt.json"),
        raising=False,
    )

    code = module.main(
        [
            "--app-root",
            "D:/sli/app",
            "--bin-dir",
            "D:/PostgreSQL/18/bin",
            "--data-dir",
            "D:/pgdata",
            "--database",
            "sli_local",
            "--apply",
            "--confirm-plan",
            confirmation,
        ]
    )

    output = capsys.readouterr()
    assert code == 0
    assert seen == [
        ("synthetic-admin", "synthetic-owner-password", plan, confirmation)
    ]
    assert "synthetic-admin" not in output.out
    assert json.loads(output.out) == {
        "confirmation_sha256": confirmation,
        "mode": "apply",
        "receipt": str(Path("D:/receipt.json")),
        "status": "complete",
    }


def test_main_writes_only_sanitized_failure_to_status_file(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """Catches losing an interactive failure or persisting its sensitive cause."""
    module = _bootstrap_module()
    status_file = tmp_path / "status.json"
    monkeypatch.setattr(module.getpass, "getpass", lambda _prompt: "synthetic-admin")

    def fail(_opts, _password):
        raise module.BootstrapError("postgres_admin_connection_failed")

    monkeypatch.setattr(module, "prepare_live_plan", fail)

    code = module.main(
        [
            "--app-root",
            "D:/sli/app",
            "--bin-dir",
            "D:/PostgreSQL/18/bin",
            "--data-dir",
            "D:/pgdata",
            "--database",
            "sli_local",
            "--status-file",
            str(status_file),
        ]
    )

    assert code == 2
    assert json.loads(status_file.read_text(encoding="utf-8")) == {
        "code": "postgres_admin_connection_failed",
        "status": "error",
    }
    assert "synthetic-admin" not in status_file.read_text(encoding="utf-8")
    assert "synthetic-admin" not in capsys.readouterr().err


def test_main_can_read_admin_password_once_from_stdin(monkeypatch, capsys) -> None:
    """Catches forcing secrets into argv when getpass has no child console."""
    module = _bootstrap_module()
    seen = []
    plan = {"operation": "bootstrap_existing_postgresql_18", "database": "sli_local"}
    monkeypatch.setattr(
        module.sys,
        "stdin",
        io.StringIO("synthetic-admin\nsynthetic-owner-password\n"),
    )
    monkeypatch.setattr(
        module,
        "prepare_live_plan",
        lambda _opts, password: seen.append(password) or plan,
    )

    code = module.main(
        [
            "--app-root",
            "D:/sli/app",
            "--bin-dir",
            "D:/PostgreSQL/18/bin",
            "--data-dir",
            "D:/pgdata",
            "--database",
            "sli_local",
            "--admin-password-stdin",
        ]
    )

    output = capsys.readouterr()
    assert code == 0
    assert seen == ["synthetic-admin"]
    assert "synthetic-admin" not in output.out
    assert "synthetic-admin" not in output.err


def test_direct_cli_failure_writes_safe_status_without_traceback(tmp_path: Path) -> None:
    """Catches script-mode imports bypassing the sanitized error boundary."""
    app_root = tmp_path / "app"
    bin_dir = tmp_path / "bin"
    data_dir = tmp_path / "data"
    for directory in (app_root, bin_dir, data_dir):
        directory.mkdir()
    status_file = tmp_path / "status.json"

    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "maintenance" / "existing_postgres_bootstrap.py"),
            "--app-root",
            str(app_root),
            "--bin-dir",
            str(bin_dir),
            "--data-dir",
            str(data_dir),
            "--database",
            "sli_local",
            "--admin-password-stdin",
            "--status-file",
            str(status_file),
        ],
        input="synthetic-admin\n",
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        cwd=tmp_path,
    )

    assert result.returncode == 2
    assert "Traceback" not in result.stderr
    assert "synthetic-admin" not in result.stderr
    assert json.loads(status_file.read_text(encoding="utf-8")) == {
        "code": "required_path_missing",
        "status": "error",
    }


def test_apply_after_plan_reuses_one_stdin_password_for_exact_live_plan(
    monkeypatch, capsys
) -> None:
    """Catches requiring a second password entry between plan and apply."""
    module = _bootstrap_module()
    plan = {"operation": "bootstrap_existing_postgresql_18", "database": "sli_local"}
    confirmation = module.plan_confirmation(plan)
    seen = []
    monkeypatch.setattr(
        module.sys,
        "stdin",
        io.StringIO("synthetic-admin\nsynthetic-owner-password\n"),
    )
    monkeypatch.setattr(module, "prepare_live_plan", lambda _opts, _password: plan)
    monkeypatch.setattr(
        module,
        "perform_apply",
        lambda _opts, password, owner_password, plan_value, confirmation_value: seen.append(
            (password, owner_password, plan_value, confirmation_value)
        )
        or Path("D:/receipt.json"),
    )

    code = module.main(
        [
            "--app-root",
            "D:/sli/app",
            "--bin-dir",
            "D:/PostgreSQL/18/bin",
            "--data-dir",
            "D:/pgdata",
            "--database",
            "sli_local",
            "--admin-password-stdin",
            "--platform-owner-password-stdin",
            "--apply-after-plan",
        ]
    )

    output = capsys.readouterr()
    assert code == 0
    assert seen == [
        ("synthetic-admin", "synthetic-owner-password", plan, confirmation)
    ]
    assert "synthetic-admin" not in output.out
    assert json.loads(output.out)["status"] == "complete"


@pytest.fixture
def bootstrap_postgres_cluster(monkeypatch):
    """Explicit opt-in owns a whole fresh cluster, never an external DSN."""
    if os.environ.get("SLI_BOOTSTRAP_DISPOSABLE_CLUSTER") != "1":
        if any(str(os.environ.get(key) or "").strip() for key in (
            "SLI_BOOTSTRAP_TEST_PG_DSN", "SLI_BOOTSTRAP_TEST_PSQL",
        )):
            pytest.fail(
                "legacy bootstrap configuration is unsupported; replace it with "
                "SLI_BOOTSTRAP_DISPOSABLE_CLUSTER=1 and SLI_BOOTSTRAP_TEST_PG_BIN "
                "pointing to installed official PG18 binaries on Linux as a non-root user"
            )
        pytest.skip("set SLI_BOOTSTRAP_DISPOSABLE_CLUSTER=1 for a private PG18 cluster")
    from bootstrap_cluster import owned_cluster

    bin_dir = os.environ.get("SLI_BOOTSTRAP_TEST_PG_BIN")
    if not bin_dir:
        pytest.fail("set SLI_BOOTSTRAP_TEST_PG_BIN to an installed official PG18 bin directory; Linux/nonroot required")
    # libpq and the schema subprocess must not inherit another cluster's service,
    # options, credentials or report-domain setting.
    for key in tuple(os.environ):
        if key.upper().startswith("PG") or key == "ADLOG_REPORT_DOMAIN_FQDN":
            monkeypatch.delenv(key, raising=False)
    with owned_cluster(Path(bin_dir)) as cluster:
        yield cluster


@pytest.mark.postgres_integration
@pytest.mark.postgres_owned_cluster
def test_full_postgresql18_forward_chain_in_isolated_cluster(bootstrap_postgres_cluster) -> None:
    """Catches a source migration that cannot bootstrap one empty PG18 cluster."""
    import psycopg
    from bootstrap_cluster import assert_owned_connection

    cluster = bootstrap_postgres_cluster
    module = _bootstrap_module()
    host, port, password = cluster.host, cluster.port, ""
    primary = cluster.database
    psql_value = str(cluster.psql)
    dsn = {"host": host, "port": port, "user": "postgres", "password": password,
           "dbname": "postgres", "connect_timeout": 5}
    runtime_password = "synthetic-runtime-password"
    migrations = module.forward_migration_inventory(
        ROOT / "config" / "postgres_migrations"
    )

    with psycopg.connect(**dsn, autocommit=True) as admin:
        assert_owned_connection(admin, cluster)
        snapshot = module.read_cluster_snapshot(admin, database=primary)
        # Every cluster-wide role belongs to this unique private fixture.
        assert snapshot.server_version_num // 10000 == 18
        assert snapshot.database_exists is False
        assert snapshot.runtime_role_exists is False
        module.create_target_database(
            admin,
            database=primary,
            runtime_password=runtime_password,
        )

    plan = module.build_plan(
        database=primary,
        expected_data_directory=snapshot.data_directory,
        snapshot=snapshot,
        schema_sha256="1" * 64,
        roles_sha256="2" * 64,
        migrations=migrations,
    )
    base_markers = module.base_schema_markers(ROOT / "config" / "postgres_schema.sql")
    plan.update(
        {
            "base_markers": [
                {"version": version, "name": name}
                for version, name in base_markers
            ],
            "expected_marker_count": len(base_markers) + len(migrations),
            "paths": {"app_root": str(ROOT), "psql": psql_value},
            "source_identity": {
                "domain_fqdn": "example.test",
                "forest_fqdn": "example.test",
                "domain_sid": None,
                "basis": "domain_controllers",
            },
        }
    )
    opts = SimpleNamespace(host=host, port=port)

    module._apply_database_schema(
        opts=opts,
        database=primary,
        admin_password=password,
        runtime_password=runtime_password,
        platform_owner_password="synthetic-owner-password",
        plan=plan,
    )
    expected = module._expected_ledger(plan)
    with psycopg.connect(
        host=host,
        port=port,
        dbname=primary,
        user="postgres",
        password=password,
        autocommit=True,
    ) as connection:
        assert_owned_connection(connection, cluster)
        module.verify_exact_ledger(module._read_ledger(connection), expected)
        module._verify_target_readback(connection, len(expected))


def test_child_environment_passes_only_validated_report_domain():
    from scripts.maintenance.existing_postgres_bootstrap import _child_environment

    environment = _child_environment(
        Path("D:/PostgreSQL/18/bin/psql.exe"), "synthetic-password",
        {"ADLOG_REPORT_DOMAIN_FQDN": " Corp.Example.TEST ", "PGOPTIONS": "-c role=other"},
    )
    assert environment["PGOPTIONS"] == "-c sli.report_domain_fqdn=corp.example.test"
    assert "ADLOG_REPORT_DOMAIN_FQDN" not in environment


def test_storage_lifecycle_role_inventory():
    inventory = _bootstrap_module().forward_migration_inventory(ROOT / "config/postgres_migrations")
    assert [(i.version, i.name) for i in inventory if i.version == 319] == [(319, "storage_lifecycle_roles")]
    for suffix in (".sql", ".rollback.sql"):
        sql = (ROOT / f"config/postgres_migrations/319_storage_lifecycle_roles{suffix}").read_text("utf-8")
        assert "version=318 and name='semantic_pending_candidates'" in sql


def test_storage_lifecycle_evidence_inventory():
    inventory = _bootstrap_module().forward_migration_inventory(ROOT / "config/postgres_migrations")
    assert [(i.version, i.name) for i in inventory if i.version == 321] == [(321, "storage_lifecycle_evidence")]
    for suffix in (".sql", ".rollback.sql"):
        sql = (ROOT / f"config/postgres_migrations/321_storage_lifecycle_evidence{suffix}").read_text("utf-8")
        assert "version=320 and name='semantic_import_summary'" in sql
        assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in sql
        assert "set local role adlog_storage_owner" in sql


def test_detector_query_paths_inventory():
    inventory = _bootstrap_module().forward_migration_inventory(ROOT / "config/postgres_migrations")
    assert [(i.version, i.name) for i in inventory if i.version == 324] == [(324, "detector_query_paths")]
    for suffix in (".sql", ".rollback.sql"):
        sql = (ROOT / f"config/postgres_migrations/324_detector_query_paths{suffix}").read_text("utf-8")
        assert "version=323 and name='workstation_projection_drain'" in sql
        assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in sql
        assert "set local role adlog_storage_owner" in sql


def test_t109_workstation_path_inventory():
    inventory = _bootstrap_module().forward_migration_inventory(ROOT / "config/postgres_migrations")
    assert [(i.version, i.name) for i in inventory if i.version == 325] == [(325, "t109_workstation_path")]
    for suffix in (".sql", ".rollback.sql"):
        sql = (ROOT / f"config/postgres_migrations/325_t109_workstation_path{suffix}").read_text("utf-8")
        assert "version=324 and name='detector_query_paths'" in sql
        assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in sql
        assert "set local role adlog_storage_owner" in sql


def test_nps_threshold_paths_inventory():
    inventory = _bootstrap_module().forward_migration_inventory(ROOT / "config/postgres_migrations")
    assert [(i.version, i.name) for i in inventory if i.version == 326] == [(326, "nps_threshold_paths")]
    for suffix in (".sql", ".rollback.sql"):
        sql = (ROOT / f"config/postgres_migrations/326_nps_threshold_paths{suffix}").read_text("utf-8")
        assert "version=325 and name='t109_workstation_path'" in sql
        assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in sql
        assert "set local role adlog_storage_owner" in sql


def test_detector_remaining_paths_inventory():
    inventory = _bootstrap_module().forward_migration_inventory(ROOT / "config/postgres_migrations")
    assert [(i.version, i.name) for i in inventory if i.version == 327] == [(327, "detector_remaining_paths")]
    for suffix in (".sql", ".rollback.sql"):
        sql = (ROOT / f"config/postgres_migrations/327_detector_remaining_paths{suffix}").read_text("utf-8")
        assert "version=326 and name='nps_threshold_paths'" in sql
        assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in sql
        assert "set local role adlog_storage_owner" in sql


def test_storage_lifecycle_evidence_lock_inventory():
    inventory = _bootstrap_module().forward_migration_inventory(ROOT / "config/postgres_migrations")
    assert [(i.version, i.name) for i in inventory if i.version == 328] == [(328, "storage_lifecycle_evidence_lock")]
    for suffix in (".sql", ".rollback.sql"):
        sql = (ROOT / f"config/postgres_migrations/328_storage_lifecycle_evidence_lock{suffix}").read_text("utf-8")
        assert "version=327 and name='detector_remaining_paths'" in sql
        assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in sql
        assert "set local role adlog_storage_owner" in sql


def test_storage_lifecycle_copy_links_inventory():
    inventory = _bootstrap_module().forward_migration_inventory(ROOT / "config/postgres_migrations")
    assert [(i.version, i.name) for i in inventory if i.version == 329] == [(329, "storage_lifecycle_copy_links")]
    for suffix in (".sql", ".rollback.sql"):
        sql = (ROOT / f"config/postgres_migrations/329_storage_lifecycle_copy_links{suffix}").read_text("utf-8")
        assert "version=328 and name='storage_lifecycle_evidence_lock'" in sql
        assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in sql
        assert "set local role adlog_storage_owner" in sql
        assert "drop index concurrently" in sql


def test_storage_lifecycle_agent_continuity_inventory():
    inventory = _bootstrap_module().forward_migration_inventory(ROOT / "config/postgres_migrations")
    assert [(i.version, i.name) for i in inventory if i.version == 330] == [(330, "storage_lifecycle_agent_continuity")]
    for suffix in (".sql", ".rollback.sql"):
        sql = (ROOT / f"config/postgres_migrations/330_storage_lifecycle_agent_continuity{suffix}").read_text("utf-8")
        assert "version=329 and name='storage_lifecycle_copy_links'" in sql
        assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in sql
        assert "set local role adlog_storage_owner" in sql
        assert "sli_lifecycle_receipt_gap_v330" not in sql
    sql = (ROOT / "config/postgres_migrations/330_storage_lifecycle_agent_continuity.sql").read_text("utf-8")
    assert "create index" not in sql
    assert "when 'continuity' then" in sql
    for relation in ("raw_log_files", "sli_agent_receipts", "sli_agent_packet_inbox",
                     "source_capture_continuity_declarations"):
        assert f"lock table public.{relation} in share mode nowait" in sql
    assert "sli_agent_audit" not in sql


def test_semantic_producer_coverage_331_inventory():
    inventory = _bootstrap_module().forward_migration_inventory(ROOT / "config/postgres_migrations")
    assert [(i.version, i.name) for i in inventory if i.version == 331] == [(331, "semantic_producer_coverage")]
    for suffix in (".sql", ".rollback.sql"):
        sql = (ROOT / f"config/postgres_migrations/331_semantic_producer_coverage{suffix}").read_text("utf-8")
        assert "version=330 and name='storage_lifecycle_agent_continuity'" in sql
        assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in sql
        assert "set local role adlog_storage_owner" in sql
        assert "create index" not in sql


def test_semantic_backfill_window_332_inventory():
    inventory = _bootstrap_module().forward_migration_inventory(ROOT / "config/postgres_migrations")
    assert [(i.version, i.name) for i in inventory if i.version == 332] == [(332, "semantic_backfill_window")]
    for suffix in (".sql", ".rollback.sql"):
        sql = (ROOT / f"config/postgres_migrations/332_semantic_backfill_window{suffix}").read_text("utf-8")
        assert "version=331 and name='semantic_producer_coverage'" in sql
        assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in sql
        assert "set local role adlog_storage_owner" in sql
        assert "create index" not in sql


def test_storage_lifecycle_wait_333_inventory():
    inventory = _bootstrap_module().forward_migration_inventory(ROOT / "config/postgres_migrations")
    assert [(i.version, i.name) for i in inventory if i.version == 333] == [(333, "storage_lifecycle_wait")]
    for suffix in (".sql", ".rollback.sql"):
        sql = (ROOT / f"config/postgres_migrations/333_storage_lifecycle_wait{suffix}").read_text("utf-8")
        assert "version=332 and name='semantic_backfill_window'" in sql
        assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in sql
        assert "set local role adlog_storage_owner" in sql
        assert "create index" not in sql


def test_account_decoy_restore_334_inventory():
    inventory = _bootstrap_module().forward_migration_inventory(ROOT / "config/postgres_migrations")
    assert [(i.version, i.name) for i in inventory if i.version == 334] == [(334, "account_decoy_restore")]
    for suffix in (".sql", ".rollback.sql"):
        sql = (ROOT / f"config/postgres_migrations/334_account_decoy_restore{suffix}").read_text("utf-8")
        assert "version=333 and name='storage_lifecycle_wait'" in sql
        assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in sql
        assert "set local role adlog_storage_owner" in sql
        assert "create index" not in sql
