"""Fresh-stand bootstrap and pinned, resumable migrations (never production)."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import psycopg
from psycopg import sql

from deploy.linux import backup
from deploy.linux.installed_state import migration_checksum_variants
from scripts.maintenance.existing_postgres_bootstrap import (
    base_schema_markers,
    create_platform_owner,
    forward_migration_inventory,
    load_baseline,
    render_baseline_schema,
)
from server.sli.core.secret_files import secret_value

ROOT = Path(__file__).resolve().parents[2]
STAND = Path(__file__).resolve().parent
# Preserve the patchable module used by the shared temporary-directory helper.
tempfile = backup.tempfile

WORKER_LOGINS = (
    ("sli_notification_login", "adlog_notification_worker", "SLI_NOTIFICATION_DB_PASSWORD"),
    ("sli_report_producer_login", "adlog_report_producer", "SLI_REPORT_PRODUCER_PG_PASSWORD"),
    ("sli_semantic_login", "adlog_semantic_worker", "ADLOG_SEMANTIC_WORKER_PASSWORD"),
    ("sli_storage_login", "adlog_storage_worker", "ADLOG_STORAGE_V2_WORKER_PASSWORD"),
    ("sli_context_login", "adlog_context_worker", "ADLOG_AD_CONTEXT_WORKER_PASSWORD"),
    ("sli_storage_lifecycle_login", "adlog_storage_lifecycle_worker", "ADLOG_STORAGE_LIFECYCLE_PASSWORD"),
    ("sli_storage_lifecycle_delete_login", "adlog_storage_lifecycle_delete", "ADLOG_STORAGE_LIFECYCLE_DELETE_PASSWORD"),
)


def configure_worker_logins(connection) -> None:
    """Provision dedicated NOINHERIT logins after the canonical roles exist."""
    # Run candidate code here: the accepted upgrade coordinator can predate
    # these settings. Its fenced/checkpointed migration must provision them too.
    if os.environ.get("SLI_DEPLOYMENT_MODE") == "native":
        from deploy.linux.sli_secrets import ensure

        directory = Path("/etc/sli/secrets")
        ensure(directory, names=["storage_lifecycle_password", "storage_lifecycle_delete_password", "report_producer_password"])
        for setting, name in (("ADLOG_STORAGE_LIFECYCLE_PASSWORD", "storage_lifecycle_password"),
                              ("ADLOG_STORAGE_LIFECYCLE_DELETE_PASSWORD", "storage_lifecycle_delete_password"),
                              ("SLI_REPORT_PRODUCER_PG_PASSWORD", "report_producer_password")):
            os.environ.setdefault(setting + "_FILE", str(directory / name))
    for login, role, setting in WORKER_LOGINS:
        if f"{setting}_FILE" not in os.environ:
            if role in {"adlog_storage_lifecycle_worker", "adlog_storage_lifecycle_delete"}:
                continue  # Frozen Python/Compose layouts do not use the .NET worker.
            if role in {"adlog_notification_worker", "adlog_report_producer"}:
                continue  # Older/custom layouts without these services.
            raise ValueError("missing worker secret file")
        password = secret_value(setting)
        with connection.transaction():
            # Password literals must not appear in PostgreSQL statement/error logs.
            connection.execute("set local log_statement = 'none'")
            connection.execute("set local log_min_error_statement = 'panic'")
            connection.execute("set local log_error_verbosity = 'terse'")
            exists = connection.execute("select 1 from pg_roles where rolname=%s", (login,)).fetchone()
            if not exists:
                connection.execute(sql.SQL("create role {} nologin").format(sql.Identifier(login)))
            else:
                # A pre-existing login must not retain access beyond its one
                # worker role (including direct ACLs or object ownership).
                row = connection.execute("""
                    WITH login AS (SELECT * FROM pg_roles WHERE rolname=%s)
                    SELECT EXISTS (
                        SELECT 1 FROM login WHERE rolsuper OR rolcreatedb OR rolcreaterole
                            OR rolreplication OR rolbypassrls
                        UNION ALL
                        SELECT 1 FROM pg_auth_members m, login l
                            WHERE m.member=l.oid AND m.roleid<>(SELECT oid FROM pg_roles WHERE rolname=%s)
                        UNION ALL
                        SELECT 1 FROM pg_class c, login l WHERE c.relowner=l.oid
                        UNION ALL
                        SELECT 1 FROM pg_namespace n, login l WHERE n.nspowner=l.oid
                        UNION ALL
                        SELECT 1 FROM pg_proc p, login l WHERE p.proowner=l.oid
                        UNION ALL
                        SELECT 1 FROM pg_database d, login l WHERE d.datdba=l.oid
                        UNION ALL
                        SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a, login l
                            WHERE a.grantee=l.oid
                        UNION ALL
                        SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) a, login l
                            WHERE a.grantee=l.oid
                        UNION ALL
                        SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a, login l
                            WHERE a.grantee=l.oid
                    )
                """, (login, role)).fetchone()
                if not row or row[0]:
                    raise RuntimeError("linux_worker_login_privileges_mismatch")
            connection.execute(sql.SQL(
                "alter role {} login noinherit nosuperuser nocreatedb nocreaterole "
                "noreplication nobypassrls password {}"
            ).format(sql.Identifier(login), sql.Literal(password)))
            inheritance = "true" if role == "adlog_notification_worker" else "false"
            connection.execute(sql.SQL("grant {} to {} with inherit " + inheritance).format(
                sql.Identifier(role), sql.Identifier(login),
            ))
            connection.execute(sql.SQL("grant connect on database sli to {}").format(sql.Identifier(login)))
            if role == "adlog_report_producer":
                # Admission pins both the dedicated login name and its current
                # OID. Re-running install/upgrade repairs a recreated login.
                connection.execute("delete from public.report_producer_principals where principal_name=%s", (login,))
                connection.execute("insert into public.report_producer_principals "
                                   "select oid,rolname from pg_catalog.pg_roles where rolname=%s", (login,))
    configure_job_logins(connection)


def configure_job_logins(connection) -> None:
    """Provision configured executor profiles; their roles log in without SET ROLE."""
    profiles = ("light", "heavy", "long") if (
        os.environ.get("SLI_CORE_JOB_RADIUS_PILOT", "0") == "1"
        or os.environ.get("SLI_CORE_JOB_AD_GPO_PILOT", "0") == "1") else ("light",)
    settings = [f"SLI_JOB_{purpose.upper()}_{profile.upper()}_PASSWORD_FILE"
                for profile in profiles for purpose in ("dispatcher", "executor", "publisher")]
    explicitly_enabled = any(os.environ.get("SLI_CORE_JOB_" + flag) == "1" for flag in (
        "RADIUS_PILOT", "AD_GPO_PILOT", "WORKSTATIONS_RETENTION", "WORKSTATIONS_PROJECTION"))
    # Disabled executors without configured credentials need no logins. A
    # partial profile or explicit opt-in fails closed before any login changes.
    if not explicitly_enabled and not any(setting in os.environ for setting in settings):
        return
    if any(setting not in os.environ for setting in settings):
        raise ValueError("missing executor secret file")
    for profile in profiles:
        for purpose in ("dispatcher", "executor", "publisher"):
            role = f"sli_job_{purpose}_{profile}"
            setting = f"SLI_JOB_{purpose.upper()}_{profile.upper()}_PASSWORD"
            password = secret_value(setting)
            with connection.transaction():
                connection.execute("set local log_statement = 'none'")
                connection.execute("set local log_min_error_statement = 'panic'")
                connection.execute("set local log_error_verbosity = 'terse'")
                row = connection.execute("""
                    select rolsuper or rolcreatedb or rolcreaterole or rolreplication or rolbypassrls or rolinherit
                        or exists(select 1 from pg_class c where c.relowner=r.oid)
                        or exists(select 1 from pg_namespace n where n.nspowner=r.oid)
                        or exists(select 1 from pg_proc p where p.proowner=r.oid)
                        or exists(select 1 from pg_database d where d.datdba=r.oid)
                        or has_schema_privilege(r.oid,'public','CREATE')
                        or exists(select 1 from pg_auth_members m where m.member=r.oid
                            and not (r.rolname='sli_job_publisher_light'
                                and m.roleid='adlog_radius_session_consumer'::regrole
                                and m.inherit_option and not m.set_option))
                    from pg_roles r where r.rolname=%s
                """, (role,)).fetchone()
                if not row or row[0]:
                    raise RuntimeError("executor_login_privileges_mismatch")
                connection.execute(sql.SQL(
                    "alter role {} login noinherit nosuperuser nocreatedb nocreaterole "
                    "noreplication nobypassrls password {}"
                ).format(sql.Identifier(role), sql.Literal(password)))
                connection.execute(sql.SQL("grant connect on database sli to {}").format(sql.Identifier(role)))


def configure_workstation_history() -> None:
    if os.environ.get("SLI_CORE_JOB_WORKSTATIONS_RETENTION", "0") != "1":
        return
    from server.sli.storage.workstation_history import configured_history, ensure_schema

    history = configured_history()
    if history is None:
        raise RuntimeError("workstation_history_unavailable")
    ensure_schema(history.port)


def configure_permanent_history() -> None:
    """Prepare copy-only history before Compose admits the lifecycle worker."""
    from server.sli.storage import ad_snapshot_change_history, permanent_fact_history

    if not permanent_fact_history.primary_read_enabled():
        return
    port = permanent_fact_history.configured_read_port()
    if port is None:
        raise RuntimeError("permanent_history_unavailable")
    permanent_fact_history.ensure_schema(port)
    ad_snapshot_change_history.ensure_schema(port)


def pgpass_escape(value: str) -> str:
    return backup.pgpass_escape(value)


def _sql_failure(paths: list[Path], passfile: Path, stderr: str) -> str:
    from deploy.linux.native_pg_migrate import psql_error_tail

    lines = stderr.splitlines()
    for line in lines:
        match = re.fullmatch(r"psql:(.+):(\d+): (ERROR|FATAL|PANIC|error): (.+)", line)
        if match and (source := Path(match[1])) in paths:
            message = match[4].replace(str(passfile), "[redacted]")
            diagnostic = psql_error_tail(f"{match[3].upper()}: {message}")
            return f"{source.name}:{match[2]}: {diagnostic}"

    files = ", ".join(path.name for path in paths)
    for line in lines:
        if line.startswith("psql: error: "):
            message = line.removeprefix("psql: error: ").replace(str(passfile), "[redacted]")
            return f"{files}: {psql_error_tail(f'ERROR: {message}')}"
    return f"PostgreSQL failed while running {files}"


def run_sql(paths: list[Path], *, passfile: Path, atomic: bool = False) -> None:
    from deploy.linux import operation_wait

    command = ["psql", "-X", "--no-password", "--quiet", "--set", "ON_ERROR_STOP=1", "--set", "VERBOSITY=terse",
               *backup.postgres_target().arguments(), "--dbname", "sli"]
    if atomic:
        command.append("--single-transaction")
    for path in paths:
        command.extend(["--file", str(path)])
    # No inherited credentials, password argv, or password-valued environment.
    environment = {"PATH": os.environ.get("PATH", ""), "PGPASSFILE": str(passfile),
                   "PGCONNECT_TIMEOUT": "5", "PGCLIENTENCODING": "UTF8"}
    # The passfile is issued for the sli database only.
    with backup.pg_connect(passfile, 'sli', autocommit=True) as connection:
        size = connection.execute("SELECT pg_database_size('sli')").fetchone()[0]
    watch = operation_wait.Watch('migration', minimum=21600, size=size, history=operation_wait.history_path())
    import uuid
    application = os.environ.get('PGAPPNAME', 'sli_migration_' + uuid.uuid4().hex)
    environment['PGAPPNAME'] = application
    environment['PGOPTIONS'] = f'-c statement_timeout={int(watch.limit * 1000)}'
    with tempfile.TemporaryFile() as stderr:
        # psql has no parallel clients; retain the coordinator's process group
        # so cancelling its Python process also stops this migration client.
        result = subprocess.Popen(command, env=environment, stdout=subprocess.DEVNULL, stderr=stderr)
        operation_wait.wait_process(result, watch, lambda: operation_wait.postgres_probe(passfile, application))
        if result.returncode:
            # Keep only the primary error. SQL output, DETAIL and CONTEXT can contain private data.
            end = stderr.seek(0, os.SEEK_END)
            stderr.seek(max(0, end - backup.PG_DIAGNOSTIC_BYTES))
            error = stderr.read().decode("utf-8", errors="replace")
            print(_sql_failure(paths, passfile, error), file=sys.stderr, flush=True)
            raise RuntimeError("linux_sql_step_failed")
    watch.success()


def apply_pending(connection, migrations, expected: dict[int, str], execute, *, baseline_version: int) -> None:
    """Reject foreign/partial ledgers; resume only exact admitted versions.

    A fresh stand holds the whole baseline. A restored existing database may
    lag behind the baseline, but only as a contiguous tail after its newest
    applied version; a hole in the middle is never filled implicitly.
    """
    applied = dict(connection.execute(
        "select version, name from public.schema_migrations order by version"
    ).fetchall())
    if any(expected.get(version) != name for version, name in applied.items()):
        raise RuntimeError("linux_migration_ledger_mismatch")
    newest = max(applied, default=0)
    if not applied or any(version < newest and version not in applied for version in expected):
        raise RuntimeError("linux_baseline_ledger_incomplete")
    for migration in migrations:
        if migration.version in applied:
            continue
        execute([migration.path])
        row = connection.execute(
            "select name from public.schema_migrations where version = %s", (migration.version,)
        ).fetchone()
        if row != (migration.name,):
            raise RuntimeError("linux_migration_readback_failed")


def attest_ledger(connection, migrations, expected, *, write=False):
    """Pin exact IDs, names and source hashes without rewriting an attestation."""
    schema_hash = hashlib.sha256((ROOT / "config/postgres_schema_v8.sql").read_bytes()).hexdigest()
    hashes = {version: schema_hash for version, _ in base_schema_markers(ROOT / "config/postgres_schema_v8.sql")}
    hashes.update((item.version, item.sha256) for item in migrations)
    schema_variants = migration_checksum_variants((ROOT / "config/postgres_schema_v8.sql").read_bytes())
    variants = {version: schema_variants for version, _ in base_schema_markers(ROOT / "config/postgres_schema_v8.sql")}
    variants.update((item.version, migration_checksum_variants(item.path.read_bytes())) for item in migrations)
    rows = connection.execute(
        "select version, name, to_jsonb(m)->>'sha256' from public.schema_migrations m order by version"
    ).fetchall()
    for version, name, checksum in rows:
        if expected.get(version) != name or (checksum is not None and checksum not in variants.get(version, ())):
            raise RuntimeError("linux_migration_checksum_mismatch")
    if write:
        if [(version, name) for version, name, _ in rows] != sorted(expected.items()):
            raise RuntimeError("linux_migration_ledger_mismatch")
        with connection.transaction():
            for version, _, checksum in rows:
                if checksum is None:
                    connection.execute("update public.schema_migrations set sha256=%s where version=%s and sha256 is null",
                                       (hashes[version], version))


def migrate() -> None:
    seed_domain = os.environ.get("SLI_INSTALL_SEED_REPORT_DOMAIN", "1")
    if seed_domain not in {"0", "1"}:
        raise ValueError("linux_report_domain_seed_invalid")
    inventory = forward_migration_inventory(ROOT / "config/postgres_migrations")
    # The verified manifest pins every migration up to its baseline version;
    # later migrations come from the same reviewed repository revision.
    admitted = list(inventory)
    baseline = load_baseline(ROOT / "config/postgres_baseline", admitted)
    expected = dict(base_schema_markers(ROOT / "config/postgres_schema_v8.sql"))
    expected.update((item.version, item.name) for item in admitted)
    if (("SLI_PG_ADMIN_PASSWORD_FILE" not in os.environ and "SLI_PG_ADMIN_PASSFILE" not in os.environ)
            or "SLI_PLATFORM_OWNER_PASSWORD_FILE" not in os.environ):
        raise ValueError("missing bootstrap secret file")
    owner_password = secret_value("SLI_PLATFORM_OWNER_PASSWORD")
    with (backup.helper_temporary_directory(prefix="sli-migrate-") as temporary,
          backup.pg_passfile(database="sli", reader=lambda: secret_value("SLI_PG_ADMIN_PASSWORD")) as passfile):
        with psycopg.connect(**backup.postgres_target().connection(), dbname="sli", passfile=str(passfile),
                             connect_timeout=5, autocommit=True) as connection:
            connection.execute("select pg_advisory_lock(hashtext('sli_linux_stand_migrate'))")
            execute = lambda paths: run_sql(paths, passfile=passfile)
            exists = connection.execute("select to_regclass('public.schema_migrations')").fetchone()[0]
            if exists is None:
                # Roles and schema are one transaction; a failure leaves no
                # partial baseline/roles and can be retried on the same volume.
                rendered = render_baseline_schema(
                    baseline, os.environ.get("SLI_INSTALL_DOMAIN", ""),
                    Path(temporary) / "baseline.sql", seed_report_domain=seed_domain == "1",
                )
                # Seed only in the fresh baseline transaction. A failed seed
                # rolls back bootstrap; retries and restored databases keep
                # their existing policy configuration.
                run_sql([baseline.roles_path, rendered, STAND / "runtime_grants.sql",
                         STAND / "default_semantic_policy.sql"],
                        passfile=passfile, atomic=True)
            attest_ledger(connection, admitted, expected)
            apply_pending(connection, admitted, expected, execute, baseline_version=baseline.version)
            attest_ledger(connection, admitted, expected, write=True)
            if os.environ.get("SLI_DEPLOYMENT_MODE") == "native":
                from deploy.linux.native_plugins import bootstrap
                bootstrap(connection)
            # Retry this idempotent step even after an interrupted first start.
            with connection.transaction():
                create_platform_owner(connection, owner_password)
                if os.environ.get("SLI_NATIVE_OWNER_SETUP") == "1":
                    # Fresh native installs have an empty versioned owner table.
                    # Preserve established owners; never promote another account.
                    connection.execute("""insert into public.access_platform_owners(user_id, owner_key, business_reason)
                        select id, 'primary', 'Initial server owner'
                        from public.auth_users where username='platform-owner' and is_active=true
                        and not exists(select 1 from public.access_platform_owners where owner_key='primary')
                        on conflict(user_id) do nothing""")
            # Idempotent: also removes legacy ownership introduced by updates.
            execute([STAND / "runtime_grants.sql"])
            connection.execute("revoke create on schema public from public, adlog_user")
            configure_worker_logins(connection)
    configure_permanent_history()
    configure_workstation_history()
    print("linux_migrations_verified")
