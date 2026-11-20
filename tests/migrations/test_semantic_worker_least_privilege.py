from __future__ import annotations

from pathlib import Path

import pytest

from server.sli.semantic.semantic_worker_connection import (
    assert_semantic_worker_least_privilege,
)


ROOT = Path(__file__).resolve().parents[2]


class Cursor:
    def __init__(self, row: dict[str, object]) -> None:
        self.row = row
        self.sql = ""

    def execute(self, sql, _params=()) -> None:
        self.sql = str(sql)

    def fetchone(self):
        return self.row


def _role_row(**overrides) -> dict[str, object]:
    row: dict[str, object] = {
        "current_role": "adlog_semantic_worker",
        "session_role": "adlog_semantic_login",
        "current_superuser": False,
        "current_createdb": False,
        "current_createrole": False,
        "current_replication": False,
        "current_bypassrls": False,
        "session_superuser": False,
        "session_createdb": False,
        "session_createrole": False,
        "session_replication": False,
        "session_bypassrls": False,
        "unauthorized_memberships": [],
        "owned_relations": 0,
        "owned_schemas": 0,
        "direct_relation_grants": 0,
        "direct_schema_grants": 0,
        "direct_function_grants": 0,
    }
    row.update(overrides)
    return row


def test_least_privilege_preflight_accepts_only_exact_role() -> None:
    result = assert_semantic_worker_least_privilege(Cursor(_role_row()))

    assert result["current_role"] == "adlog_semantic_worker"
    assert result["elevated_privileges"] is False


@pytest.mark.parametrize(
    "overrides",
    [
        {"current_role": "adlog_storage_worker"},
        {"current_superuser": True},
        {"session_createdb": True},
        {"session_bypassrls": True},
        {"unauthorized_memberships": ["adlog_user"]},
        {"owned_relations": 1},
        {"direct_relation_grants": 1},
    ],
)
def test_least_privilege_preflight_rejects_wrong_or_elevated_role(
    overrides,
) -> None:
    with pytest.raises(RuntimeError):
        assert_semantic_worker_least_privilege(Cursor(_role_row(**overrides)))


def test_migration_050_grants_only_bounded_semantic_runtime_surface() -> None:
    forward = (
        ROOT
        / "config/postgres_migrations/050_semantic_worker_least_privilege.sql"
    ).read_text(encoding="utf-8").lower()
    rollback = (
        ROOT
        / "config/postgres_migrations/050_semantic_worker_least_privilege.rollback.sql"
    ).read_text(encoding="utf-8").lower()
    roles = (
        ROOT / "config/postgres_migrations/storage_v2_roles.sql"
    ).read_text(encoding="utf-8").lower()

    assert "values (50,'semantic_worker_least_privilege')" in forward
    assert "adlog_semantic_worker nologin nosuperuser nocreatedb nocreaterole noinherit nobypassrls noreplication" in roles
    assert "\n    events," not in forward
    assert "observed_entities" not in forward
    assert "findings" not in forward
    assert "runtime_worker_heartbeats" in forward
    assert "grant select,insert,update on table" in forward
    assert "create role" not in forward
    assert "drop role" not in rollback
    assert "revoke all privileges" in rollback


def test_semantic_runtime_schema_guard_has_exact_reversible_grant() -> None:
    migration = (
        ROOT
        / "config/postgres_migrations/054_semantic_worker_runtime_schema_guard.sql"
    ).read_text(encoding="utf-8").casefold()
    rollback = (
        ROOT
        / "config/postgres_migrations/054_semantic_worker_runtime_schema_guard.rollback.sql"
    ).read_text(encoding="utf-8").casefold()

    assert "grant select on table schema_migrations to adlog_semantic_worker" in migration
    assert "version=53 and name='semantic_canonical_action_risk'" in migration
    assert "revoke select on table schema_migrations from adlog_semantic_worker" in rollback
    assert "where version=54 and name='semantic_worker_runtime_schema_guard'" in rollback
