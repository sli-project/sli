"""Provision dedicated native worker logins using the installed PostgreSQL schema."""

import os
import secrets
import stat
from pathlib import Path
from tempfile import NamedTemporaryFile

from psycopg import sql

from deploy.linux.native_credentials import secret_value

PASSWORD_NAMES = (
    "storage_lifecycle_password", "storage_lifecycle_delete_password", "report_producer_password",
)
MAX_PASSWORD_BYTES = 1024 * 1024


def password_metadata(path, *, directory=False):
    info = path.lstat()
    kind, mode = (stat.S_ISDIR, 0o750) if directory else (stat.S_ISREG, 0o640)
    if (not kind(info.st_mode) or info.st_uid != 0 or info.st_gid != 10001
            or stat.S_IMODE(info.st_mode) & ~mode or not directory and not info.st_mode & stat.S_IRGRP
            or any(name.startswith("system.posix_acl_") for name in os.listxattr(path))):
        raise ValueError("native_worker_secret_unprotected")


def protect_password(path, mode):
    for name in os.listxattr(path):
        if name.startswith("system.posix_acl_"):
            os.removexattr(path, name)
    os.chown(path, 0, 10001)
    path.chmod(mode)


def ensure_passwords(directory):
    """Preflight the selected core passwords before publishing any missing file."""
    if os.geteuid() != 0:
        raise ValueError("linux_root_required")
    directory = Path(directory)
    try:
        directory.mkdir(mode=0o700, parents=True)
    except FileExistsError:
        pass
    else:
        protect_password(directory, 0o750)
    password_metadata(directory, directory=True)
    pending = []
    for name in PASSWORD_NAMES:
        path = directory / name
        try:
            password_metadata(path)
        except FileNotFoundError:
            pending.append(path)
            continue
        with path.open("rb") as stream:
            body = stream.read(MAX_PASSWORD_BYTES + 1)
        if not body or len(body) > MAX_PASSWORD_BYTES or any(c in body for c in (b"\r", b"\n", b"\x00")):
            raise ValueError("native_worker_secret_invalid")
        body.decode("ascii")
    for path in pending:
        with NamedTemporaryFile(prefix=".sli-secret-", dir=directory, delete=False) as stream:
            temporary = Path(stream.name)
            try:
                stream.write(secrets.token_urlsafe(48).encode("ascii"))
                stream.flush()
                os.fsync(stream.fileno())
                protect_password(temporary, 0o640)
                os.link(temporary, path)
                descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            finally:
                temporary.unlink(missing_ok=True)


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
