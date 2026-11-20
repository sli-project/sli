"""Process-scoped least-privilege credentials for production semantics."""
from __future__ import annotations

from contextlib import contextmanager
import os
import re
import secrets
from typing import Iterator, MutableMapping
from uuid import uuid4


_ROLE_PATTERN = re.compile(r"adlog_semantic_runtime_[0-9a-f]{16}")


def _admin_dsn() -> str:
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    source = os.getenv("ADLOG_PG_DSN", "").strip()
    user = os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
    password = os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
    if not source or not user or not password:
        raise RuntimeError("protected PostgreSQL migration credentials are required")
    parts = conninfo_to_dict(source)
    parts.update(user=user, password=password)
    return make_conninfo(**parts)


def connect_admin(*, autocommit: bool = True):
    import psycopg
    from psycopg.rows import dict_row

    return psycopg.connect(
        _admin_dsn(),
        autocommit=autocommit,
        row_factory=dict_row,
        connect_timeout=5,
        application_name="sli_semantic_production_credentials",
        options="-c statement_timeout=30000 -c lock_timeout=5000",
    )


def _database_name(cur) -> str:
    database_name = str(cur.connection.info.dbname or "").strip()
    if not database_name:
        raise RuntimeError("semantic runtime database identity is unavailable")
    return database_name


def grant_ephemeral_login_connect(cur, role: str) -> None:
    from psycopg import sql

    cur.execute(
        sql.SQL("grant connect on database {} to {}").format(
            sql.Identifier(_database_name(cur)),
            sql.Identifier(role),
        )
    )


def revoke_ephemeral_login_connect(cur, role: str) -> None:
    from psycopg import sql

    cur.execute(
        sql.SQL("revoke connect on database {} from {}").format(
            sql.Identifier(_database_name(cur)),
            sql.Identifier(role),
        )
    )


def create_ephemeral_login(cur) -> tuple[str, str]:
    from psycopg import sql

    role = f"adlog_semantic_runtime_{uuid4().hex[:16]}"
    if _ROLE_PATTERN.fullmatch(role) is None:
        raise RuntimeError("generated semantic runtime role is invalid")
    password = secrets.token_urlsafe(36)
    cur.execute(
        sql.SQL(
            "create role {} login noinherit nosuperuser nocreatedb "
            "nocreaterole nobypassrls noreplication password {}"
        ).format(sql.Identifier(role), sql.Literal(password))
    )
    cur.execute(
        sql.SQL("grant adlog_semantic_worker to {}").format(sql.Identifier(role))
    )
    # The portable local bootstrap revokes CONNECT from PUBLIC.  The login is
    # deliberately NOINHERIT, so it needs this one direct database privilege
    # in order to connect and explicitly SET ROLE to the bounded worker role.
    grant_ephemeral_login_connect(cur, role)
    return role, password


def drop_ephemeral_login(cur, role: str) -> None:
    from psycopg import sql

    if _ROLE_PATTERN.fullmatch(role) is None:
        raise RuntimeError("refusing unexpected semantic runtime role name")
    revoke_ephemeral_login_connect(cur, role)
    cur.execute(sql.SQL("drop role if exists {}").format(sql.Identifier(role)))


def worker_dsn(*, role: str, password: str) -> str:
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    parts = conninfo_to_dict(os.environ["ADLOG_PG_DSN"])
    parts.update(user=role, password=password)
    return make_conninfo(**parts)


@contextmanager
def ephemeral_worker_environment(
    environ: MutableMapping[str, str] | None = None,
) -> Iterator[str]:
    """Expose a worker DSN only while the process-owned login exists."""
    target = environ if environ is not None else os.environ
    previous = target.get("ADLOG_SEMANTIC_WORKER_DSN")
    role = ""
    try:
        with connect_admin(autocommit=True) as conn, conn.cursor() as cur:
            role, password = create_ephemeral_login(cur)
        target["ADLOG_SEMANTIC_WORKER_DSN"] = worker_dsn(
            role=role,
            password=password,
        )
        yield role
    finally:
        if previous is None:
            target.pop("ADLOG_SEMANTIC_WORKER_DSN", None)
        else:
            target["ADLOG_SEMANTIC_WORKER_DSN"] = previous
        if role:
            with connect_admin(autocommit=True) as conn, conn.cursor() as cur:
                drop_ephemeral_login(cur, role)
