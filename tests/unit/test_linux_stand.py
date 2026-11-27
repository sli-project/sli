# ruff: noqa: F811 -- imported pytest fixtures are intentionally named as parameters
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from deploy.linux import entrypoint, healthcheck, migrate, restore_existing
from scripts.maintenance.existing_postgres_bootstrap import (
    forward_migration_inventory,
    load_baseline,
)
from tests.tooling.test_release_package import (
    signed_package,  # noqa: F401 - shared pytest fixture
)

ROOT = Path(__file__).resolve().parents[2]
STAND = ROOT / "deploy/linux"
MANIFEST_BASELINE = int(json.loads((ROOT / "config/postgres_baseline/manifest.json").read_text(encoding="utf-8"))["baseline_version"])


def test_package_verification_image_can_verify_without_checkout(signed_package, tmp_path):
    """Catch missing runtime dependencies in the verification image's COPY list."""
    source = Path(__file__).resolve().parents[2]
    image = tmp_path / "image"
    image.mkdir()
    dockerfile = source / "deploy/Dockerfile.package-verification"
    for line in dockerfile.read_text(encoding="utf-8").splitlines():
        if not line.startswith("COPY "):
            continue
        *sources, destination = shlex.split(line)[1:]
        for name in sources:
            target = image / destination
            if (source / name).is_dir():
                shutil.copytree(source / name, target, dirs_exist_ok=True)
            else:
                if destination.endswith("/"):
                    target = target / Path(name).name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source / name, target)
    archive, trust = signed_package()
    script = f"""
import sys
from pathlib import Path
sys.path.insert(0, {str(image)!r})
from deploy.linux import release_package
from deploy.linux.release_package import verify_package
assert Path(release_package.__file__).resolve().is_relative_to(Path({str(image)!r}))
assert verify_package(Path({str(archive)!r}), Path({str(trust)!r})).manifest['package_id'] == 'sli.core'
print('package_image_verifier_verified')
"""
    result = subprocess.run([sys.executable, "-I", "-B", "-c", script], cwd=image,
                            capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "package_image_verifier_verified"


class Ledger:
    def __init__(self, rows):
        self.rows = dict(rows)

    def execute(self, statement, params=None):
        if params:
            name = self.rows.get(params[0])
            return SimpleNamespace(fetchone=lambda: (name,) if name else None)
        return SimpleNamespace(fetchall=lambda: list(self.rows.items()))


def test_migrations_resume_only_missing_and_read_back_exact_marker():
    connection = Ledger({144: "baseline", 145: "first"})
    migrations = [SimpleNamespace(version=n, name=name, path=Path(str(n)))
                  for n, name in [(145, "first"), (146, "second")]]
    calls = []

    def execute(paths):
        calls.append(paths)
        connection.rows[146] = "second"

    migrate.apply_pending(connection, migrations, {144: "baseline", 145: "first", 146: "second"}, execute, baseline_version=144)
    assert calls == [[Path("146")]]
    calls.clear()
    migrate.apply_pending(connection, migrations, {144: "baseline", 145: "first", 146: "second"}, execute, baseline_version=144)
    assert calls == []


@pytest.mark.parametrize("failure", ["seed", "owner"])
@pytest.mark.parametrize("seed_domain", ["0", "1"])
def test_fresh_bootstrap_and_resume_after_setup_failure(tmp_path, monkeypatch, capsys, failure, seed_domain):
    inventory = forward_migration_inventory(ROOT / "config/postgres_migrations")
    expected = dict(migrate.base_schema_markers(ROOT / "config/postgres_schema_v8.sql"))
    expected.update((item.version, item.name) for item in inventory)
    owner_attempts = []
    bootstrap_attempts = []
    steps = []

    class Connection(Ledger):
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def transaction(self):
            return self

        def execute(self, statement, params=None):
            if not isinstance(statement, str):
                return SimpleNamespace(fetchone=lambda: None)
            if "pg_advisory_lock" in statement or statement.startswith("revoke"):
                return None
            if "to_regclass" in statement:
                return SimpleNamespace(fetchone=lambda: ("schema_migrations" if self.rows else None,))
            return super().execute(statement, params)

    connection = Connection({})

    def run_sql(paths, *, passfile, atomic=False):
        assert passfile.is_file()
        steps.append((paths, atomic))
        if atomic:
            bootstrap_attempts.append(paths)
            assert paths[0].name == "roles.sql"
            assert "__SLI_REPORT_DOMAIN__" not in paths[1].read_text(encoding="utf-8")
            assert ("VALUES ('reports.domain_fqdn', 'stand.example.invalid', 'installer')" in paths[1].read_text(encoding="utf-8")) == (seed_domain == "1")
            assert paths[2].name == "runtime_grants.sql"
            assert paths[3] == STAND / "default_semantic_policy.sql"
            if failure == "seed" and len(bootstrap_attempts) == 1:
                raise RuntimeError("synthetic interruption")
            connection.rows.update({version: name for version, name in expected.items()
                                    if version <= MANIFEST_BASELINE})
        elif paths[0].name != "runtime_grants.sql":
            version = int(paths[0].name.split("_", 1)[0])
            connection.rows[version] = expected[version]

    def create_owner(conn, password):
        assert conn is connection
        owner_attempts.append(password)
        if failure == "owner" and len(owner_attempts) == 1:
            raise RuntimeError("synthetic interruption")

    temporary_directory = migrate.tempfile.TemporaryDirectory
    monkeypatch.setattr(migrate.tempfile, "TemporaryDirectory", lambda **kw: temporary_directory(dir=tmp_path, **kw))
    monkeypatch.setattr(migrate.psycopg, "connect", lambda **kw: connection)
    monkeypatch.setattr(migrate, "run_sql", run_sql)
    monkeypatch.setattr(migrate, "create_platform_owner", create_owner)
    monkeypatch.setattr(migrate, "attest_ledger", lambda *args, **kwargs: None)
    monkeypatch.setenv("SLI_INSTALL_DOMAIN", "stand.example.invalid")
    monkeypatch.setenv("SLI_INSTALL_SEED_REPORT_DOMAIN", seed_domain)
    for key in ("SLI_PG_ADMIN_PASSWORD", "SLI_PLATFORM_OWNER_PASSWORD",
                "ADLOG_SEMANTIC_WORKER_PASSWORD", "ADLOG_STORAGE_V2_WORKER_PASSWORD",
                "ADLOG_AD_CONTEXT_WORKER_PASSWORD", "SLI_NOTIFICATION_DB_PASSWORD"):
        secret = tmp_path / key
        secret.write_text("synthetic-only-password\n", encoding="utf-8")
        monkeypatch.delenv(key, raising=False)
        monkeypatch.setenv(f"{key}_FILE", str(secret))
    with pytest.raises(RuntimeError, match="synthetic interruption"):
        migrate.migrate()
    assert sum(atomic for _, atomic in steps) == 1
    assert connection.rows == (expected if failure == "owner" else {})
    steps.clear()
    migrate.migrate()
    assert len(owner_attempts) == (2 if failure == "owner" else 1)
    if failure == "owner":
        assert [(paths[0].name, atomic) for paths, atomic in steps] == [("runtime_grants.sql", False)]
    else:
        assert sum(atomic for _, atomic in steps) == 1
        assert connection.rows == expected
    assert capsys.readouterr().out == "linux_migrations_verified\n"


def test_migrate_rejects_invalid_report_domain_seed_before_connecting(monkeypatch):
    monkeypatch.setenv("SLI_INSTALL_SEED_REPORT_DOMAIN", "invalid")
    monkeypatch.setattr(migrate.psycopg, "connect", lambda **kw: pytest.fail("must not connect"))
    with pytest.raises(ValueError, match="linux_report_domain_seed_invalid"):
        migrate.migrate()


@pytest.mark.parametrize("rows", [{144: "wrong"}, {144: "baseline", 999: "foreign"}, {}])
def test_migrations_reject_foreign_or_incomplete_ledger(rows):
    with pytest.raises(RuntimeError):
        migrate.apply_pending(Ledger(rows), [], {144: "baseline"}, lambda _: pytest.fail("must not execute"), baseline_version=144)


def test_restored_database_catches_up_on_baseline_tail():
    connection = Ledger({148: "a", 149: "b"})
    migrations = [SimpleNamespace(version=n, name=name, path=Path(str(n)))
                  for n, name in [(148, "a"), (149, "b"), (150, "c"), (151, "d")]]
    executed = []

    def execute(paths):
        executed.extend(int(path.name) for path in paths)
        connection.rows[int(paths[0].name)] = {150: "c", 151: "d"}[int(paths[0].name)]

    migrate.apply_pending(connection, migrations, {148: "a", 149: "b", 150: "c", 151: "d"}, execute,
                          baseline_version=150)
    assert executed == [150, 151]


def test_restored_database_with_hole_is_rejected():
    with pytest.raises(RuntimeError, match="baseline_ledger_incomplete"):
        migrate.apply_pending(Ledger({147: "a", 149: "c"}), [], {147: "a", 148: "b", 149: "c"},
                              lambda _: pytest.fail("must not execute"), baseline_version=150)


def test_migration_requires_successful_readback():
    with pytest.raises(RuntimeError, match="readback_failed"):
        migrate.apply_pending(Ledger({144: "baseline"}),
                              [SimpleNamespace(version=145, name="first", path=Path("145"))],
                              {144: "baseline", 145: "first"}, lambda _: None, baseline_version=144)


def test_sql_reports_failing_file_and_safe_error(monkeypatch, tmp_path, capsys):
    from deploy.linux import backup, operation_wait
    from tests.unit.linux_operation_process import completed
    captured = {}
    passfile = tmp_path / "private-passfile"
    baseline, migration = tmp_path / "baseline.sql", tmp_path / "421_synthetic.sql"

    def run(command, **kwargs):
        captured.update(command=command, **kwargs)
        kwargs["stderr"].write((
            f"psql:{migration}:12: ERROR: permission denied for table findings\n"
            "DETAIL: synthetic private database row\n"
            "CONTEXT: SQL statement with a synthetic private value\n"
            f'psql: warning: password file "{passfile}" has invalid permissions\n'
            "ERROR: connection postgresql://example:example-secret@db.example.test/sli\n"
        ).encode("utf-8"))
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(migrate.subprocess, "run", run)
    monkeypatch.setattr(migrate.subprocess, 'Popen', lambda *a, **kw: completed(run(*a, **kw)))
    monkeypatch.setattr(backup, 'pg_connect', lambda *a, **kw: nullcontext(SimpleNamespace(
        execute=lambda *a: SimpleNamespace(fetchone=lambda: (4096,)))))
    monkeypatch.setattr(operation_wait, 'history_path', lambda: tmp_path / 'summary.json')
    monkeypatch.setenv("PGPASSWORD", "synthetic password")
    with pytest.raises(RuntimeError, match="^linux_sql_step_failed$"):
        migrate.run_sql([baseline, migration], passfile=passfile, atomic=True)
    assert "--single-transaction" in captured["command"]
    assert captured["stdout"] == subprocess.DEVNULL
    assert captured["env"]["PGPASSFILE"] == str(passfile)
    assert "PGPASSWORD" not in captured["env"]
    assert "synthetic password" not in " ".join(captured["command"])
    stderr = capsys.readouterr().err
    assert "421_synthetic.sql:12: ERROR: permission denied for table findings" in stderr
    for private in ("baseline.sql", passfile.name, "synthetic private", "example-secret", "postgresql://"):
        assert private not in stderr


def test_pgpass_escaping_and_line_injection():
    assert migrate.pgpass_escape(r"synthetic:back\slash") == r"synthetic\:back\\slash"
    with pytest.raises(ValueError):
        migrate.pgpass_escape("synthetic\nline")


def test_optional_executor_login_provisioning_is_inert_when_disabled(monkeypatch):
    monkeypatch.delenv("SLI_CORE_JOB_RADIUS_PILOT", raising=False)
    monkeypatch.setenv("SLI_CORE_JOB_WORKSTATIONS_PROJECTION", "0")
    migrate.configure_job_logins(None)


def test_default_projection_without_executor_configuration_needs_no_logins(monkeypatch):
    for flag in ("RADIUS_PILOT", "AD_GPO_PILOT", "WORKSTATIONS_RETENTION", "WORKSTATIONS_PROJECTION"):
        monkeypatch.delenv("SLI_CORE_JOB_" + flag, raising=False)
    for purpose in ("DISPATCHER", "EXECUTOR", "PUBLISHER"):
        monkeypatch.delenv(f"SLI_JOB_{purpose}_LIGHT_PASSWORD_FILE", raising=False)
    migrate.configure_job_logins(None)


@pytest.mark.parametrize("configured", ["explicit", "DISPATCHER", "EXECUTOR", "PUBLISHER"])
def test_executor_configuration_cannot_silently_accept_missing_credentials(monkeypatch, configured):
    for flag in ("RADIUS_PILOT", "AD_GPO_PILOT", "WORKSTATIONS_RETENTION", "WORKSTATIONS_PROJECTION"):
        monkeypatch.delenv("SLI_CORE_JOB_" + flag, raising=False)
    for purpose in ("DISPATCHER", "EXECUTOR", "PUBLISHER"):
        monkeypatch.delenv(f"SLI_JOB_{purpose}_LIGHT_PASSWORD_FILE", raising=False)
    if configured == "explicit":
        monkeypatch.setenv("SLI_CORE_JOB_WORKSTATIONS_PROJECTION", "1")
    else:
        monkeypatch.setenv(f"SLI_JOB_{configured}_LIGHT_PASSWORD_FILE", "synthetic-file")
    with pytest.raises(ValueError, match="^missing executor secret file$"):
        migrate.configure_job_logins(None)


def test_executor_login_uses_its_profile_role_directly(monkeypatch):
    monkeypatch.setenv("SLI_CORE_JOB_RADIUS_PILOT", "1")
    monkeypatch.setattr(migrate, "secret_value", lambda _: "synthetic-password")
    for profile in ("light", "heavy", "long"):
        for purpose in ("dispatcher", "executor", "publisher"):
            monkeypatch.setenv(f"SLI_JOB_{purpose.upper()}_{profile.upper()}_PASSWORD_FILE", "synthetic-file")
    calls = []
    class Connection:
        def transaction(self):
            return nullcontext()
        def execute(self, statement, params=None):
            calls.append((statement, params))
            return SimpleNamespace(fetchone=lambda: (False,))
    migrate.configure_job_logins(Connection())
    role_checks = [params[0] for statement, params in calls if isinstance(statement, str) and "from pg_roles" in statement]
    assert len(role_checks) == 9 and len(set(role_checks)) == 9
    assert all(name.startswith("sli_job_") for name in role_checks)
    assert not any(isinstance(statement, str) and "set role" in statement.lower() for statement, _ in calls)


def test_stand_baseline_follows_verified_manifest():
    inventory = forward_migration_inventory(ROOT / "config/postgres_migrations")
    baseline = load_baseline(ROOT / "config/postgres_baseline", inventory)
    manifest = json.loads((ROOT / "config/postgres_baseline/manifest.json").read_text(encoding="utf-8"))
    assert baseline.version == int(manifest["baseline_version"])
    assert not (STAND / "migrations.json").exists()


@pytest.mark.parametrize("nonempty,replace,allowed", [(False, False, True), (True, False, False), (True, True, True)])
def test_restore_requires_empty_database_or_explicit_flag(nonempty, replace, allowed):
    connection = SimpleNamespace(execute=lambda _: SimpleNamespace(fetchone=lambda: (nonempty,)))
    if allowed:
        restore_existing.require_empty_database(connection, replace_existing=replace)
    else:
        with pytest.raises(RuntimeError, match="^linux_restore_requires_empty_database$"):
            restore_existing.require_empty_database(connection)


def test_restore_command_preserves_ownership_parallel_jobs_and_private_password(tmp_path, monkeypatch):
    captured = {}
    monkeypatch.setattr(restore_existing.operation_wait, 'native_rate', lambda _: 1)
    monkeypatch.setattr(restore_existing.operation_wait, 'history_path', lambda: tmp_path / 'summary.json')

    def run(command, **kwargs):
        captured.update(command=command, **kwargs)
        return SimpleNamespace(returncode=0, poll=lambda: 0, wait=lambda: 0)

    monkeypatch.setattr(restore_existing.subprocess, "Popen", run)
    monkeypatch.setenv("PGPASSWORD", "synthetic-private")
    restore_existing.run_restore(tmp_path, passfile=tmp_path / "pgpass", jobs=3, replace_existing=False)
    assert "--jobs=3" in captured["command"]
    assert "--format=directory" in captured["command"]
    assert not {"--no-owner", "--no-acl", "--clean", "--if-exists"}.intersection(captured["command"])
    assert captured["env"]["PGPASSFILE"] == str(tmp_path / "pgpass")
    assert "PGPASSWORD" not in captured["env"]
    assert captured["stdout"] == subprocess.DEVNULL
    assert captured["stderr"] is not None
    restore_existing.run_restore(tmp_path, passfile=tmp_path / "pgpass", jobs=3, replace_existing=True)
    assert {"--clean", "--if-exists"}.issubset(captured["command"])


def test_restore_cli_redacts_database_failure(tmp_path, monkeypatch, capsys):
    def fail(*args, **kwargs):
        raise RuntimeError("synthetic private SQL row and password")

    monkeypatch.setattr(restore_existing, "restore_existing", fail)
    assert restore_existing.main([str(tmp_path)]) == 1
    assert capsys.readouterr().err == "linux_restore_failed\n"


@pytest.mark.parametrize("nonempty", [False, True])
def test_restore_flow_roles_then_dump_then_normal_migration(tmp_path, monkeypatch, nonempty):
    dump = tmp_path / "dump"
    dump.mkdir()
    (dump / "toc.dat").write_bytes(b"synthetic dump header")
    (tmp_path / "roles.sql").write_text("CREATE ROLE synthetic_role;\n")
    secret = tmp_path / "password"
    secret.write_text("synthetic-only-password", encoding="utf-8")
    monkeypatch.delenv("SLI_PG_ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("SLI_PG_ADMIN_PASSWORD_FILE", str(secret))
    steps = []

    class Connection:
        def execute(self, query):
            return SimpleNamespace(fetchone=lambda: (nonempty,))

    monkeypatch.setattr(restore_existing.psycopg, "connect", lambda **kw: nullcontext(Connection()))
    original_temp = migrate.tempfile.TemporaryDirectory
    monkeypatch.setattr(migrate.tempfile, "TemporaryDirectory", lambda **kw: original_temp(dir=tmp_path, **kw))

    def roles(paths, **kwargs):
        steps.append("roles")
        text = paths[0].read_text(encoding="utf-8")
        assert "IF NOT EXISTS" in text
        assert "CREATE ROLE adlog_semantic_worker" in text
        assert kwargs["atomic"] is True
        assert kwargs["passfile"].is_file()

    monkeypatch.setattr(migrate, "run_sql", roles)
    monkeypatch.setattr(restore_existing, "run_restore", lambda *a, **kw: steps.append("dump"))
    monkeypatch.setattr(restore_existing, "restore_roles", lambda *a: steps.append("source_roles"))
    monkeypatch.setattr(restore_existing, "analyze_postgres", lambda *a: steps.append("analyze"))
    monkeypatch.setattr(restore_existing, "reconcile_owner", lambda *a, **kw: steps.append("owner"))
    monkeypatch.setattr(restore_existing.backup, "pg_connect", lambda *a, **kw: nullcontext(Connection()))
    monkeypatch.setattr(migrate, "migrate", lambda: steps.append("migrate_and_grants"))
    if nonempty:
        with pytest.raises(RuntimeError, match="requires_empty_database"):
            restore_existing.restore_existing(dump)
        assert steps == []
    else:
        restore_existing.restore_existing(dump)
        assert steps == ["roles", "source_roles", "dump", "migrate_and_grants", "owner", "analyze"]


def test_worker_login_provisioning_is_bounded_and_uses_secret_files(tmp_path, monkeypatch):
    statements = []

    class Connection:
        def transaction(self):
            return nullcontext()

        def execute(self, query, params=None):
            statements.append(query.as_string() if hasattr(query, "as_string") else query)
            return SimpleNamespace(fetchone=lambda: None)

    for login, role, setting in migrate.WORKER_LOGINS:
        secret = tmp_path / setting
        secret.write_text("synthetic-only-password", encoding="utf-8")
        monkeypatch.delenv(setting, raising=False)
        monkeypatch.setenv(setting + "_FILE", str(secret))
    migrate.configure_worker_logins(Connection())
    for login, role, setting in migrate.WORKER_LOGINS:
        inheritance = "true" if role == "adlog_notification_worker" else "false"
        assert any(f'grant "{role}" to "{login}" with inherit {inheritance}' == sql for sql in statements)
        assert any(f'alter role "{login}" login noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls' in sql for sql in statements)
        assert setting not in os.environ
    assert statements.count("set local log_statement = 'none'") == len(migrate.WORKER_LOGINS)
    assert statements.count("set local log_min_error_statement = 'panic'") == len(migrate.WORKER_LOGINS)


@pytest.mark.parametrize("unexpected_privileges", [False, True])
def test_existing_worker_login_cannot_keep_unbounded_privileges(tmp_path, monkeypatch, unexpected_privileges):
    changes = []

    class Connection:
        def transaction(self):
            return nullcontext()

        def execute(self, query, params=None):
            if not isinstance(query, str):
                changes.append(query.as_string())
            if isinstance(query, str) and "WITH login AS" in query:
                assert "aclexplode" in query and "rolsuper" in query and "pg_auth_members" in query
                return SimpleNamespace(fetchone=lambda: (unexpected_privileges,))
            return SimpleNamespace(fetchone=lambda: (1,))

    for login, role, setting in migrate.WORKER_LOGINS:
        secret = tmp_path / setting
        secret.write_text("synthetic-only-password", encoding="utf-8")
        monkeypatch.setenv(setting + "_FILE", str(secret))
        monkeypatch.delenv(setting, raising=False)
    if unexpected_privileges:
        with pytest.raises(RuntimeError, match="^linux_worker_login_privileges_mismatch$"):
            migrate.configure_worker_logins(Connection())
        assert changes == []
    else:
        migrate.configure_worker_logins(Connection())
        assert len(changes) == 3 * len(migrate.WORKER_LOGINS)
