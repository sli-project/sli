from pathlib import Path

from server.sli.storage.storage_v2_archive import ARCHIVE_KINDS


FORWARD = Path("config/postgres_migrations/021_storage_v2_entity_detail_kind.sql")
ROLLBACK = Path("config/postgres_migrations/021_storage_v2_entity_detail_kind.rollback.sql")


def test_runtime_and_postgres_contract_include_entity_detail() -> None:
    forward = FORWARD.read_text(encoding="utf-8").lower()

    assert "entity_detail" in ARCHIVE_KINDS
    assert forward.count("'entity_detail'") == 2
    assert "storage_v2_archive_sets_archive_kind_check" in forward
    assert "storage_v2_archive_blocks_archive_kind_check" in forward
    assert "pg_has_role(session_user, 'adlog_storage_owner', 'member')" in forward
    assert "set local role adlog_storage_owner" in forward
    assert "values (21, 'storage_v2_entity_detail_kind')" in forward


def test_migration_validates_new_constraints_before_marking_complete() -> None:
    forward = FORWARD.read_text(encoding="utf-8").lower()

    marker = forward.index("insert into schema_migrations")
    assert forward.index("validate constraint storage_v2_archive_sets_archive_kind_check") < marker
    assert forward.index("validate constraint storage_v2_archive_blocks_archive_kind_check") < marker
    assert "where version=20 and name='casefold_search_indexes'" in forward
    assert "requires schema migration 020" in forward


def test_rollback_is_fail_closed_when_entity_detail_rows_exist() -> None:
    rollback = ROLLBACK.read_text(encoding="utf-8").lower()

    guard = rollback.index("rollback 021 refused: entity_detail archive rows exist")
    first_drop = rollback.index("drop constraint")
    assert guard < first_drop
    assert rollback.count("archive_kind='entity_detail'") == 2
    assert rollback.count("check (archive_kind in ('event', 'link_detail'))") == 2
    assert "pg_has_role(session_user, 'adlog_storage_owner', 'member')" in rollback
    assert "set local role adlog_storage_owner" in rollback
    assert "where version=21 and name='storage_v2_entity_detail_kind'" in rollback
