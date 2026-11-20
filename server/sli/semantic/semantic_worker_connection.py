"""Least-privilege PostgreSQL connection for the dormant semantic worker."""
from __future__ import annotations

from typing import Any

from server.sli.core.secret_files import postgres_secret_parts


SEMANTIC_WORKER_ROLE = "adlog_semantic_worker"
_PRIVILEGE_ALIASES = (
    "superuser",
    "createdb",
    "createrole",
    "replication",
    "bypassrls",
)


def assert_semantic_worker_least_privilege(cur: Any) -> dict[str, object]:
    """Refuse an elevated login or a role other than the semantic worker."""
    cur.execute(
        """
        with recursive login_role as (
            select oid, rolname
            from pg_roles
            where rolname=session_user
        ),
        granted_roles(role_oid, role_name) as (
            select granted.oid, granted.rolname
            from login_role login
            join pg_auth_members membership on membership.member=login.oid
            join pg_roles granted on granted.oid=membership.roleid
          union
            select granted.oid, granted.rolname
            from granted_roles parent
            join pg_auth_members membership on membership.member=parent.role_oid
            join pg_roles granted on granted.oid=membership.roleid
        )
        select current_user as current_role, session_user as session_role,
               active_role_record.rolsuper as current_superuser,
               active_role_record.rolcreatedb as current_createdb,
               active_role_record.rolcreaterole as current_createrole,
               active_role_record.rolreplication as current_replication,
               active_role_record.rolbypassrls as current_bypassrls,
               login_role_record.rolsuper as session_superuser,
               login_role_record.rolcreatedb as session_createdb,
               login_role_record.rolcreaterole as session_createrole,
               login_role_record.rolreplication as session_replication,
               login_role_record.rolbypassrls as session_bypassrls,
               array(
                   select role_name
                   from granted_roles
                   where role_name<>%s
                   order by role_name
               ) as unauthorized_memberships,
               (
                   select count(*)::bigint
                   from pg_class
                   where relowner=login_role_record.oid
               ) as owned_relations,
               (
                   select count(*)::bigint
                   from pg_namespace
                   where nspowner=login_role_record.oid
               ) as owned_schemas,
               (
                   select count(*)::bigint
                   from pg_class relation
                   cross join lateral aclexplode(relation.relacl) acl
                   where relation.relacl is not null
                     and acl.grantee=login_role_record.oid
               ) as direct_relation_grants,
               (
                   select count(*)::bigint
                   from pg_namespace namespace
                   cross join lateral aclexplode(namespace.nspacl) acl
                   where namespace.nspacl is not null
                     and acl.grantee=login_role_record.oid
               ) as direct_schema_grants,
               (
                   select count(*)::bigint
                   from pg_proc procedure
                   cross join lateral aclexplode(procedure.proacl) acl
                   where procedure.proacl is not null
                     and acl.grantee=login_role_record.oid
               ) as direct_function_grants
        from pg_roles active_role_record
        cross join pg_roles login_role_record
        where active_role_record.rolname=current_user
          and login_role_record.rolname=session_user
        """,
        (SEMANTIC_WORKER_ROLE,),
    )
    row = dict(cur.fetchone() or {})
    if str(row.get("current_role") or "") != SEMANTIC_WORKER_ROLE:
        raise RuntimeError("semantic worker role activation failed")
    elevated = [
        alias
        for prefix in ("current", "session")
        for alias in _PRIVILEGE_ALIASES
        if bool(row.get(f"{prefix}_{alias}"))
    ]
    if elevated:
        raise RuntimeError(
            "semantic worker refuses elevated PostgreSQL credentials"
        )
    unauthorized_memberships = tuple(row.get("unauthorized_memberships") or ())
    direct_or_owned = {
        field: int(row.get(field) or 0)
        for field in (
            "owned_relations",
            "owned_schemas",
            "direct_relation_grants",
            "direct_schema_grants",
            "direct_function_grants",
        )
        if int(row.get(field) or 0) > 0
    }
    if unauthorized_memberships or direct_or_owned:
        raise RuntimeError(
            "semantic worker login role has privileges outside its worker role"
        )
    return {
        "current_role": SEMANTIC_WORKER_ROLE,
        "session_role": str(row.get("session_role") or ""),
        "elevated_privileges": False,
        "exclusive_worker_membership": True,
        "direct_or_owned_objects": 0,
    }


def connect_semantic_worker():
    """Connect only through the explicit worker DSN and activate its NOLOGIN role."""
    import psycopg
    from psycopg.rows import dict_row

    parts = postgres_secret_parts("ADLOG_SEMANTIC_WORKER_DSN")
    if not parts:
        raise RuntimeError("ADLOG_SEMANTIC_WORKER_DSN is required")
    parts.update(
        row_factory=dict_row,
        application_name="adlog_semantic_worker",
        options="-c statement_timeout=30000 -c lock_timeout=5000",
    )
    conn = psycopg.connect(**parts)
    try:
        with conn.cursor() as cur:
            cur.execute(f"set role {SEMANTIC_WORKER_ROLE}")
            assert_semantic_worker_least_privilege(cur)
        conn.commit()
        return conn
    except BaseException:
        conn.close()
        raise
