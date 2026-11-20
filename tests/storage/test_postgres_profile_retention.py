from __future__ import annotations

from datetime import datetime, timezone


class _Cursor:
    def __init__(
        self,
        *,
        logical_link_references: int = 0,
        archive_missing: int = 0,
        candidate_records: list[dict[str, object]] | None = None,
    ) -> None:
        self.executed: list[str] = []
        self.params: list[tuple[object, ...]] = []
        self.rowcount = 0
        self.logical_link_references = logical_link_references
        self.archive_missing = archive_missing
        self.candidate_records = candidate_records

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, _params=()):
        self.executed.append(" ".join(str(sql).lower().split()))
        self.params.append(tuple(_params))
        if "delete from events_v2_core" in str(sql).lower():
            self.rowcount = len(_params[0])

    def fetchone(self):
        statement = self.executed[-1]
        if "to_regclass" in statement:
            return {"relation": "events_v2_core"}
        if "count(*) as rows_selected" in statement:
            return {"rows_selected": 2}
        if "logical_link_references" in statement:
            return {"logical_link_references": self.logical_link_references}
        if "archive_missing" in statement:
            return {"archive_missing": self.archive_missing}
        return None

    def fetchall(self):
        statement = self.executed[-1]
        if "candidate_classification" in statement:
            if self.candidate_records is not None:
                relationship_cutoff = self.params[-1][2]
                assert isinstance(relationship_cutoff, datetime)
                rows: list[dict[str, object]] = []
                for candidate in self.candidate_records:
                    if candidate["linked"]:
                        classification = (
                            "held_by_relationship_horizon"
                            if candidate["time_created_utc"] >= relationship_cutoff
                            else "held_by_other_dependency"
                        )
                    elif not candidate["archived"]:
                        classification = "held_by_archive_gap"
                    else:
                        classification = "eligible"
                    rows.append({"id": candidate["id"], "classification": classification})
                return rows
            if self.logical_link_references:
                return [
                    {"id": 1, "classification": "eligible"},
                    {"id": 2, "classification": "held_by_relationship_horizon"},
                ]
            if self.archive_missing:
                return [
                    {"id": 1, "classification": "eligible"},
                    {"id": 3, "classification": "held_by_archive_gap"},
                ]
            return [{"id": 1, "classification": "eligible"}, {"id": 2, "classification": "eligible"}]
        return []


class _Connection:
    def __init__(self, **cursor_kwargs) -> None:
        self.cursor_instance = _Cursor(**cursor_kwargs)
        self.commits = 0

    def cursor(self):
        return self.cursor_instance

    def commit(self):
        self.commits += 1


class _DirectCursor(_Cursor):
    def fetchall(self):
        statement = self.executed[-1]
        if "direct_no_archive_candidate_classification" in statement:
            return [{
                "id": 41,
                "normalized_hash": b"a" * 32,
                "classification": "eligible",
            }]
        if "from events_v2_core where id=any" in statement and "for update" in statement:
            return [{"id": 41, "normalized_hash": b"a" * 32}]
        if "delete from events_v2_core" in statement:
            return [{"id": 41}]
        return super().fetchall()

    def fetchone(self):
        statement = self.executed[-1]
        if statement == "show transaction_isolation":
            return {"transaction_isolation": "read committed"}
        if "direct_no_archive_prefilter_reconciliation" in statement:
            return {
                "expired_total_count": 1,
                "covered_by_continuity_count": 1,
                "blocked_without_continuity_count": 0,
                "blocked_by_relationship_count": 0,
                "blocked_by_archive_gap_count": 0,
                "blocked_by_restrictive_reference_count": 0,
                "eligible_count": 1,
            }
        if "direct_no_archive_remaining_readback" in statement:
            return {"remaining": 0}
        return super().fetchone()


class _DirectConnection(_Connection):
    def __init__(self) -> None:
        self.cursor_instance = _DirectCursor()
        self.commits = 0


class _NoContinuityDirectCursor(_DirectCursor):
    def fetchone(self):
        statement = self.executed[-1]
        if "direct_no_archive_prefilter_reconciliation" in statement:
            return {
                "expired_total_count": 100,
                "covered_by_continuity_count": 0,
                "blocked_without_continuity_count": 100,
                "blocked_by_relationship_count": 0,
                "blocked_by_archive_gap_count": 0,
                "blocked_by_restrictive_reference_count": 0,
                "eligible_count": 0,
            }
        return super().fetchone()

    def fetchall(self):
        if "direct_no_archive_candidate_classification" in self.executed[-1]:
            return []
        return super().fetchall()


class _NoContinuityDirectConnection(_Connection):
    def __init__(self) -> None:
        self.cursor_instance = _NoContinuityDirectCursor()
        self.commits = 0


class _CategoryMismatchDirectCursor(_DirectCursor):
    def fetchone(self):
        statement = self.executed[-1]
        if "direct_no_archive_prefilter_reconciliation" in statement:
            return {
                "expired_total_count": 2,
                "covered_by_continuity_count": 1,
                "blocked_without_continuity_count": 1,
                "blocked_by_relationship_count": 0,
                "blocked_by_archive_gap_count": 0,
                "blocked_by_restrictive_reference_count": 0,
                "eligible_count": 0,
            }
        return super().fetchone()


class _CategoryMismatchDirectConnection(_Connection):
    def __init__(self) -> None:
        self.cursor_instance = _CategoryMismatchDirectCursor()
        self.commits = 0


class _UnknownDependencyCursor(_DirectCursor):
    def fetchall(self):
        statement = self.executed[-1]
        if "direct_no_archive_restrictive_dependencies" in statement:
            return [{"dependent_relation": "unexpected_event_reference"}]
        return super().fetchall()


class _UnknownDependencyConnection(_Connection):
    def __init__(self) -> None:
        self.cursor_instance = _UnknownDependencyCursor()
        self.commits = 0


def test_no_archive_retention_dry_run_uses_exact_descriptors_and_semantic_gate() -> None:
    from server.sli.storage.postgres_profile_retention import execute_no_archive_retention

    connection = _DirectConnection()
    cutoff = datetime(2026, 8, 3, tzinfo=timezone.utc)

    result = execute_no_archive_retention(
        connection,
        cutoff=cutoff,
        apply=False,
        admitted=False,
        batch_size=100,
    )

    assert result["status"] == "ok"
    assert result["cutoff_utc"] == cutoff.isoformat()
    assert result["descriptor_identities"] == [
        {
            "source": "sli.windows.ad-dc",
            "stream": "Security",
            "event_key": event_key,
        }
        for event_key in ("4624", "4634")
    ]
    assert result["selected_count"] == 1
    assert result["eligible_count"] == 1
    assert result["deleted_count"] == 0
    assert result["delete_performed"] is False
    assert result["archive_write_performed"] is False
    assert result["dc_mutated"] is False
    selector = next(
        sql for sql in connection.cursor_instance.executed
        if "direct_no_archive_candidate_classification" in sql
    )
    assert "semantic_processing_outbox" in selector
    assert "status <> 'completed'" in selector
    assert "source_capture_continuity_declarations" in selector
    assert "descriptor_source" in selector
    assert "log_source_id" in selector
    assert "storage_v2_archive_blocks" not in selector
    assert not any(
        "delete from events_v2_core" in sql
        for sql in connection.cursor_instance.executed
    )


def test_no_archive_retention_apply_requires_admission_before_query() -> None:
    from server.sli.storage.postgres_profile_retention import execute_no_archive_retention

    connection = _DirectConnection()
    result = execute_no_archive_retention(
        connection,
        cutoff=datetime(2026, 8, 3, tzinfo=timezone.utc),
        apply=True,
        admitted=False,
    )

    assert result["status"] == "blocked"
    assert result["reason"] == "direct_no_archive_admission_missing"
    assert connection.cursor_instance.executed == []


def test_no_archive_retention_blocks_expired_rows_without_continuity_declarations() -> None:
    from server.sli.storage.postgres_profile_retention import execute_no_archive_retention

    connection = _NoContinuityDirectConnection()
    result = execute_no_archive_retention(
        connection,
        cutoff=datetime(2026, 8, 3, tzinfo=timezone.utc),
        apply=True,
        admitted=True,
        preservation_check=lambda _candidates: None,
    )

    assert result["status"] == "blocked"
    assert result["reason"] == "expired_rows_without_continuity_declarations"
    assert result["selected_count"] == 0
    assert result["expired_total_count"] == 100
    assert result["covered_by_continuity_count"] == 0
    assert result["blocked_without_continuity_count"] == 100
    assert result["blocked_by_relationship_count"] == 0
    assert result["blocked_by_archive_gap_count"] == 0
    assert result["blocked_by_restrictive_reference_count"] == 0
    assert result["eligible_count"] == 0
    assert result["remaining_count"] == 100
    assert result["deleted_count"] == 0
    assert (
        result["covered_by_continuity_count"]
        + result["blocked_without_continuity_count"]
        == result["expired_total_count"]
    )
    assert connection.commits == 0


def test_no_archive_retention_rejects_unreconciled_outcome_categories() -> None:
    import pytest

    from server.sli.storage.postgres_profile_retention import execute_no_archive_retention

    with pytest.raises(RuntimeError, match="direct_no_archive_reconciliation_category_mismatch"):
        execute_no_archive_retention(
            _CategoryMismatchDirectConnection(),
            cutoff=datetime(2026, 8, 3, tzinfo=timezone.utc),
            apply=True,
            admitted=True,
            preservation_check=lambda _candidates: None,
        )


def test_no_archive_retention_apply_commits_exact_batch_and_requires_empty_readback() -> None:
    from server.sli.storage.postgres_profile_retention import execute_no_archive_retention

    connection = _DirectConnection()
    result = execute_no_archive_retention(
        connection,
        cutoff=datetime(2026, 8, 3, tzinfo=timezone.utc),
        apply=True,
        admitted=True,
        batch_size=100,
        preservation_check=lambda _candidates: None,
    )

    assert result["status"] == "complete"
    assert result["selected_count"] == 1
    assert result["deleted_count"] == 1
    assert result["remaining_count"] == 0
    assert result["batches_committed"] == 1
    assert result["archive_rows_written"] == 0
    assert connection.commits == 1
    statements = connection.cursor_instance.executed
    lock_index = next(i for i, sql in enumerate(statements)
                      if "lock table event_entity_link_blocks_v2" in sql)
    classify_index = next(i for i, sql in enumerate(statements)
                          if "direct_no_archive_candidate_classification" in sql)
    assert lock_index < classify_index
    assert not any("event_entity_links_v2 in share mode" in sql or
                   ("from event_entity_links_v2" in sql and "for update" in sql)
                   for sql in statements)
    assert any(
        "from event_facts_v2" in sql and "for update" in sql
        for sql in statements
    )
    for sql in statements:
        if "any(" in sql and "for update" in sql:
            assert "::bigint[]" in sql
    assert any(
        "delete from events_v2_core" in sql
        and "normalized_hash" in sql
        for sql in connection.cursor_instance.executed
    )
    assert any(
        "direct_no_archive_remaining_readback" in sql
        for sql in connection.cursor_instance.executed
    )


def test_no_archive_selector_holds_every_known_durable_evidence_reference() -> None:
    from server.sli.storage.postgres_profile_retention import execute_no_archive_retention

    connection = _DirectConnection()
    execute_no_archive_retention(
        connection,
        cutoff=datetime(2026, 8, 3, tzinfo=timezone.utc),
        apply=False,
    )

    selector = next(
        sql for sql in connection.cursor_instance.executed
        if "direct_no_archive_candidate_classification" in sql
    )
    for relation in (
        "event_entity_link_blocks_v2",
        "event_links",
        "entity_state_current",
        "entity_states",
        "detections",
        "finding_evidence",
    ):
        assert relation in selector
    assert "held_by_other_dependency" in selector


def test_no_archive_retention_blocks_unknown_restrictive_dependency() -> None:
    from server.sli.storage.postgres_profile_retention import execute_no_archive_retention

    connection = _UnknownDependencyConnection()
    result = execute_no_archive_retention(
        connection,
        cutoff=datetime(2026, 8, 3, tzinfo=timezone.utc),
        apply=False,
    )

    assert result["status"] == "blocked"
    assert result["reason"] == "unknown_restrictive_dependency"
    assert result["unknown_dependencies"] == ["unexpected_event_reference"]
    assert not any(
        "direct_no_archive_candidate_classification" in sql
        for sql in connection.cursor_instance.executed
    )


def test_postgres_retention_dry_run_selects_only_allowlisted_v2_hot_rows() -> None:
    from server.sli.storage.postgres_profile_retention import execute_postgres_profile_retention
    from server.sli.storage.storage_policy import StoragePolicy

    connection = _Connection()
    result = execute_postgres_profile_retention(
        connection,
        policy=StoragePolicy(db_retention_days=7),
        now=datetime(2026, 8, 10, tzinfo=timezone.utc),
        apply=False,
    )

    assert result["mode"] == "dry-run"
    assert result["rows_selected"] == {"events_v2_core": 2}
    assert result["rows_deleted"] == {"events_v2_core": 0}
    assert connection.commits == 0
    assert not any("delete from" in sql for sql in connection.cursor_instance.executed)


def test_postgres_retention_apply_is_gated_and_preserves_control_plane() -> None:
    from server.sli.storage.postgres_profile_retention import execute_postgres_profile_retention
    from server.sli.storage.storage_policy import StoragePolicy

    blocked = execute_postgres_profile_retention(
        _Connection(),
        policy=StoragePolicy(db_retention_days=7),
        now=datetime(2026, 8, 10, tzinfo=timezone.utc),
        apply=True,
        retention_apply_by_default=False,
    )
    connection = _Connection()
    applied = execute_postgres_profile_retention(
        connection,
        policy=StoragePolicy(db_retention_days=7),
        now=datetime(2026, 8, 10, tzinfo=timezone.utc),
        apply=True,
        retention_apply_by_default=True,
    )

    assert blocked["status"] == "blocked"
    assert blocked["reason"] == "retention_apply_by_default_disabled"
    assert applied["status"] == "ok"
    assert applied["rows_deleted"] == {"events_v2_core": 2}
    assert connection.commits == 1
    assert all("storage_v2_cutover_state" not in sql for sql in connection.cursor_instance.executed)


def test_configured_retention_uses_existing_apply_default_gate() -> None:
    from server.sli.core.app_config import AdLogConfig
    from server.sli.storage.postgres_profile_retention import (
        execute_configured_postgres_profile_retention,
    )

    connection = _Connection()
    result = execute_configured_postgres_profile_retention(
        connection,
        config=AdLogConfig(
            reports_dir="data/reports",
            log_dir="data/logs",
            retention_apply_by_default=False,
        ),
        now=datetime(2026, 8, 10, tzinfo=timezone.utc),
        apply=True,
    )

    assert result["status"] == "blocked"
    assert result["reason"] == "retention_apply_by_default_disabled"


def test_postgres_retention_classifies_mixed_candidates_without_stalling_safe_deletion() -> None:
    from server.sli.storage.postgres_profile_retention import execute_postgres_profile_retention
    from server.sli.storage.storage_policy import StoragePolicy

    linked = execute_postgres_profile_retention(
        _Connection(logical_link_references=1),
        policy=StoragePolicy(db_retention_days=7),
        now=datetime(2026, 8, 10, tzinfo=timezone.utc),
    )
    unarchived = execute_postgres_profile_retention(
        _Connection(archive_missing=1),
        policy=StoragePolicy(db_retention_days=7),
        now=datetime(2026, 8, 10, tzinfo=timezone.utc),
    )

    assert linked["status"] == "ok"
    assert linked["held_by_reason"]["held_by_relationship_horizon"] == 1
    assert linked["eligible_count"] == 1
    assert unarchived["status"] == "ok"
    assert unarchived["held_by_reason"]["held_by_archive_gap"] == 1


def test_postgres_retention_apply_deletes_only_individually_eligible_candidates() -> None:
    from server.sli.storage.postgres_profile_retention import execute_postgres_profile_retention
    from server.sli.storage.storage_policy import StoragePolicy

    connection = _Connection(logical_link_references=1)
    result = execute_postgres_profile_retention(
        connection,
        policy=StoragePolicy(db_retention_days=7),
        now=datetime(2026, 8, 10, tzinfo=timezone.utc),
        apply=True,
        retention_apply_by_default=True,
    )

    assert result["status"] == "ok"
    assert result["selected_count"] == 2
    assert result["eligible_count"] == 1
    assert result["held_count"] == 1
    assert result["deleted_count"] == 1
    assert any("delete from events_v2_core" in sql for sql in connection.cursor_instance.executed)


def test_postgres_retention_uses_distinct_30_day_relationship_horizon() -> None:
    from server.sli.storage.postgres_profile_retention import execute_postgres_profile_retention
    from server.sli.storage.storage_policy import StoragePolicy

    now = datetime(2026, 8, 10, tzinfo=timezone.utc)
    connection = _Connection(candidate_records=[
        {"id": 1, "time_created_utc": datetime(2026, 7, 1, tzinfo=timezone.utc), "linked": False, "archived": True},
        {"id": 2, "time_created_utc": datetime(2026, 7, 21, tzinfo=timezone.utc), "linked": True, "archived": True},
        {"id": 3, "time_created_utc": datetime(2026, 7, 1, tzinfo=timezone.utc), "linked": True, "archived": True},
        {"id": 4, "time_created_utc": datetime(2026, 7, 1, tzinfo=timezone.utc), "linked": False, "archived": False},
    ])

    result = execute_postgres_profile_retention(
        connection,
        policy=StoragePolicy(db_retention_days=7, warm_retention_days=365),
        now=now,
        apply=True,
        retention_apply_by_default=True,
    )

    assert result["relationship_horizon_days"] == 30
    assert result["held_by_reason"] == {
        "held_by_relationship_horizon": 1,
        "held_by_archive_gap": 1,
        "held_by_other_dependency": 1,
    }
    assert result["eligible_count"] == 1
    assert result["deleted_count"] == 1
