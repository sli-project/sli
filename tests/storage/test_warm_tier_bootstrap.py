from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest


def _row(event_id: int, byte: int, when: datetime) -> dict[str, object]:
    return {
        "id": event_id,
        "normalized_hash_hex": f"{byte:02x}" * 32,
        "time_created_utc": when,
    }


def test_bootstrap_plan_is_normal_v2_incremental_contract_and_bounded(monkeypatch) -> None:
    from server.sli.storage import warm_tier_bootstrap_runtime as bootstrap

    checked = datetime(2026, 8, 2, tzinfo=timezone.utc)
    rows = [
        _row(20, 2, checked - timedelta(days=20)),
        _row(10, 1, checked - timedelta(days=19)),
    ]
    executed: list[str] = []

    class Cursor:
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def execute(self, sql, *_args): executed.append(str(sql))
        def fetchone(self): return {"checked_at_utc": checked}

    class Connection:
        def execute(self, sql): executed.append(str(sql))
        def cursor(self): return Cursor()
        def __enter__(self): return self
        def __exit__(self, *_args): return None

    monkeypatch.setattr(bootstrap, "preflight_target", lambda _port: {
        "status": "empty", "database_exists": False, "tables": [],
        "schema_fingerprint": None,
    })
    monkeypatch.setattr(bootstrap, "_connect", lambda: Connection())
    monkeypatch.setattr(bootstrap.planner, "load_storage_policy", lambda: type("P", (), {
        "db_retention_days": 7, "warm_retention_days": 365,
        "archive_auto_delete_enabled": False,
    })())
    monkeypatch.setattr(bootstrap.planner, "_source_summary", lambda *_args, **_kwargs: {
        "source_rows": 2, "source_max_event_id": 20, "appended_rows": 2,
        "eligible_rows": 2, "checked_at_utc": checked,
    })
    monkeypatch.setattr(bootstrap.planner, "_scan_missing", lambda *_args, **_kwargs: (rows, {
        "scanned_rows": 2, "already_present_rows": 0,
        "candidate_scan_complete": True, "scan_limit_reached": False,
        "checkpoint_upper_utc": checked - timedelta(days=19) + timedelta(microseconds=1),
    }))
    monkeypatch.setattr(bootstrap.planner, "_next_durable_descriptor_batch", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(bootstrap.planner, "_archive_coverage", lambda *_args, **_kwargs: {
        "missing": 0, "missing_ids": [],
    })

    plan = bootstrap.build_bootstrap_plan(batch_limit=10, scan_limit=20, port=8123)

    assert plan["package_type"] == "WARM_TIER_INCREMENTAL_PLAN"
    assert plan["contract_version"] == 2
    assert plan["status"] == "ready_for_manual_bounded_copy"
    assert plan["planned_batch"]["event_ids"] == [10, 20]
    assert plan["planned_batch"]["rows"] <= 10_000
    assert plan["selection"]["mode"] == "missing_placement_time_window_v2"
    assert plan["bootstrap"]["target_preflight"]["status"] == "empty"
    assert plan["bootstrap"]["plan_digest"] == bootstrap.plan_digest(plan)
    assert any("repeatable read read only" in sql.lower() for sql in executed)


def test_bootstrap_execution_requires_exact_digest_before_connections(monkeypatch, tmp_path: Path) -> None:
    from server.sli.storage import warm_tier_bootstrap_runtime as bootstrap

    plan = {
        "package_type": "WARM_TIER_INCREMENTAL_PLAN", "contract_version": 2,
        "bootstrap": {"contract": "sli.warm-tier-bootstrap.v1", "plan_digest": ""},
    }
    plan["bootstrap"]["plan_digest"] = bootstrap.plan_digest(plan)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    touched: list[str] = []
    monkeypatch.setattr(bootstrap, "preflight_target", lambda *_args: touched.append("preflight"))
    monkeypatch.setattr(bootstrap.copy_runtime, "execute_and_record", lambda *_args, **_kwargs: touched.append("copy"))

    with pytest.raises(ValueError, match="bootstrap_plan_digest_confirmation_required"):
        bootstrap.execute_bootstrap(plan_path, confirmation="wrong", execute=True)

    assert touched == []


def test_bootstrap_rejects_invalid_incremental_plan_before_target_initialization(monkeypatch, tmp_path: Path) -> None:
    from server.sli.storage import warm_tier_bootstrap_runtime as bootstrap

    plan = {
        "package_type": "WARM_TIER_INCREMENTAL_PLAN", "contract_version": 2,
        "bootstrap": {"contract": "sli.warm-tier-bootstrap.v1", "plan_digest": ""},
    }
    plan["bootstrap"]["plan_digest"] = bootstrap.plan_digest(plan)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    touched: list[str] = []
    monkeypatch.setattr(bootstrap.copy_runtime, "validate_plan", lambda _plan: (_ for _ in ()).throw(ValueError("normal_plan_invalid")))
    monkeypatch.setattr(bootstrap, "preflight_target", lambda *_args: touched.append("preflight"))
    monkeypatch.setattr(bootstrap, "initialize_empty_target", lambda *_args: touched.append("initialize"))

    with pytest.raises(ValueError, match="normal_plan_invalid"):
        bootstrap.execute_bootstrap(
            plan_path, confirmation=plan["bootstrap"]["plan_digest"], execute=True, port=8123,
        )

    assert touched == []


def test_bootstrap_preflight_rejects_foreign_or_occupied_target(monkeypatch) -> None:
    from server.sli.storage import warm_tier_bootstrap_runtime as bootstrap

    responses = iter([
        b'{"data":[{"rows":1}]}',
        b'{"data":[{"name":"foreign_table"}]}',
    ])
    monkeypatch.setattr(bootstrap, "_http_query", lambda *_args, **_kwargs: next(responses))

    with pytest.raises(RuntimeError, match="warm_bootstrap_target_foreign_tables"):
        bootstrap.preflight_target(8123)


def test_bootstrap_preflight_rejects_known_name_with_spoofed_engine_or_columns(monkeypatch) -> None:
    from server.sli.storage import warm_tier_bootstrap_runtime as bootstrap

    def rows(_port: int, query: str):
        if "FROM system.databases" in query:
            return [{"rows": 1}]
        if "FROM system.tables" in query:
            return [{"name": "event_placement", "engine": "View"}]
        if "FROM system.columns" in query:
            return [{"table": "event_placement", "name": "event_id", "type": "UInt64"}]
        raise AssertionError(query)

    monkeypatch.setattr(bootstrap, "_json_rows", rows)

    with pytest.raises(RuntimeError, match="warm_bootstrap_target_schema_invalid"):
        bootstrap.preflight_target(8123)


def test_bootstrap_preflight_rejects_owned_view_with_substituted_definition(monkeypatch) -> None:
    from server.sli.storage import warm_tier_bootstrap_runtime as bootstrap

    tables = [{
        "name": "sessions_effective_v1", "engine": "View",
        "as_select": "SELECT * FROM system.tables",
    }]
    monkeypatch.setattr(
        bootstrap, "_canonical_query",
        lambda _port, query: "spoofed" if "system.tables" in str(query) else "expected",
    )

    with pytest.raises(RuntimeError, match="warm_bootstrap_target_schema_invalid"):
        bootstrap._validate_owned_schema(8123, tables)


def test_bootstrap_execution_fails_when_storage_lifecycle_lock_is_held(monkeypatch, tmp_path: Path) -> None:
    from contextlib import contextmanager
    from server.sli.storage import warm_tier_bootstrap_runtime as bootstrap

    plan = {"package_type": "WARM_TIER_INCREMENTAL_PLAN", "contract_version": 2, "bootstrap": {"contract": "sli.warm-tier-bootstrap.v1", "plan_digest": ""}}
    plan["bootstrap"]["plan_digest"] = bootstrap.plan_digest(plan)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    touched: list[str] = []

    @contextmanager
    def held_lock(_connect, lock_name):
        assert lock_name == "ad_log_reports_runtime_storage_lifecycle_process"
        yield False

    monkeypatch.setattr(bootstrap.copy_runtime, "validate_plan", lambda _plan: {})
    monkeypatch.setattr(bootstrap, "session_advisory_lock", held_lock)
    monkeypatch.setattr(bootstrap, "preflight_target", lambda *_args: touched.append("preflight"))

    with pytest.raises(RuntimeError, match="warm_bootstrap_storage_lifecycle_lock_held"):
        bootstrap.execute_bootstrap(
            plan_path, confirmation=plan["bootstrap"]["plan_digest"], execute=True, port=8123,
        )

    assert touched == []


def test_bootstrap_initializes_only_base_schema_then_reuses_copy_runtime(monkeypatch, tmp_path: Path) -> None:
    from contextlib import contextmanager
    from server.sli.storage import warm_tier_bootstrap_runtime as bootstrap

    plan = {"package_type": "WARM_TIER_INCREMENTAL_PLAN", "contract_version": 2, "bootstrap": {"contract": "sli.warm-tier-bootstrap.v1", "plan_digest": ""}}
    plan["bootstrap"]["plan_digest"] = bootstrap.plan_digest(plan)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    calls: list[str] = []
    monkeypatch.setattr(bootstrap, "EVIDENCE_ROOT", tmp_path)
    monkeypatch.setattr(bootstrap.copy_runtime, "validate_plan", lambda _plan: {})
    monkeypatch.setattr(bootstrap, "preflight_target", lambda _port: {"status": "empty"})
    @contextmanager
    def lock_free(*_args):
        yield True
    monkeypatch.setattr(bootstrap, "session_advisory_lock", lock_free)
    monkeypatch.setattr(bootstrap, "initialize_empty_target", lambda _port: calls.append("initialize"))
    monkeypatch.setattr(bootstrap.copy_runtime, "execute_and_record", lambda path, **kwargs: {
        "status": "copied_and_verified", "plan": {"path": str(path)}, "safety": {},
    })

    result = bootstrap.execute_bootstrap(
        plan_path, confirmation=plan["bootstrap"]["plan_digest"], execute=True, port=8123,
    )

    assert calls == ["initialize"]
    assert result["status"] == "copied_and_verified"
    assert result["bootstrap"]["plan_digest"] == plan["bootstrap"]["plan_digest"]


def test_bootstrap_executes_the_confirmed_plan_payload_when_plan_file_is_replaced(
    monkeypatch, tmp_path: Path,
) -> None:
    from contextlib import contextmanager
    from server.sli.storage import warm_tier_bootstrap_runtime as bootstrap

    confirmed = {
        "package_type": "WARM_TIER_INCREMENTAL_PLAN", "contract_version": 2,
        "planned_batch": {"identity_sha256": "a" * 64},
        "bootstrap": {"contract": "sli.warm-tier-bootstrap.v1", "plan_digest": ""},
    }
    confirmed["bootstrap"]["plan_digest"] = bootstrap.plan_digest(confirmed)
    replacement = {
        "package_type": "WARM_TIER_INCREMENTAL_PLAN", "contract_version": 2,
        "planned_batch": {"identity_sha256": "b" * 64},
        "bootstrap": {"contract": "sli.warm-tier-bootstrap.v1", "plan_digest": ""},
    }
    replacement["bootstrap"]["plan_digest"] = bootstrap.plan_digest(replacement)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(confirmed), encoding="utf-8")
    executed: list[dict] = []

    @contextmanager
    def lock_free(*_args):
        yield True

    monkeypatch.setattr(bootstrap, "EVIDENCE_ROOT", tmp_path)
    monkeypatch.setattr(bootstrap.copy_runtime, "validate_plan", lambda plan: {
        "identity_sha256": plan["planned_batch"]["identity_sha256"],
    })
    monkeypatch.setattr(bootstrap, "session_advisory_lock", lock_free)
    monkeypatch.setattr(bootstrap, "preflight_target", lambda _port: {"status": "empty"})
    monkeypatch.setattr(
        bootstrap, "initialize_empty_target",
        lambda _port: plan_path.write_text(json.dumps(replacement), encoding="utf-8"),
    )

    def execute_and_record(_path, **kwargs):
        executed.append(kwargs["plan_payload"])
        return {"status": "copied_and_verified", "safety": {}}

    monkeypatch.setattr(bootstrap.copy_runtime, "execute_and_record", execute_and_record)

    bootstrap.execute_bootstrap(
        plan_path, confirmation=confirmed["bootstrap"]["plan_digest"],
        execute=True, port=8123,
    )

    assert executed == [confirmed]


def test_initialize_empty_target_creates_base_sessions_before_lifecycle_schema_without_legacy_manifest(monkeypatch) -> None:
    from server.sli.storage import warm_tier_bootstrap_runtime as bootstrap

    statements: list[str] = []
    monkeypatch.setattr(bootstrap, "_http_query", lambda _port, query, **_kwargs: statements.append(query) or b"")
    monkeypatch.setattr(bootstrap.copy_runtime, "_http_query", lambda _port, query, **_kwargs: statements.append(query) or b"")
    monkeypatch.setattr(bootstrap.copy_runtime, "_ensure_incremental_manifest_schema", lambda _port: statements.append("incremental_manifest"))
    monkeypatch.setattr(bootstrap.copy_runtime, "_session_schema_present", lambda _port: True)
    monkeypatch.setattr(bootstrap.copy_runtime, "_derived_output_schema_present", lambda _port: True)

    bootstrap.initialize_empty_target(8123)
    assert any("CREATE TABLE IF NOT EXISTS sli_warm.sessions" in statement for statement in statements)
    bootstrap.copy_runtime._apply_session_schema(8123)

    sessions_index = next(index for index, statement in enumerate(statements) if "CREATE TABLE IF NOT EXISTS sli_warm.sessions" in statement)
    lifecycle_index = next(index for index, statement in enumerate(statements) if "CREATE TABLE IF NOT EXISTS sli_warm.session_lifecycle_revisions" in statement)
    assert sessions_index < lifecycle_index
    assert "logon_id String" in statements[sessions_index]
    assert not any("copy_manifest" in statement for statement in statements)


def test_bootstrap_preflight_admits_empty_base_sessions(monkeypatch) -> None:
    from server.sli.storage import warm_tier_bootstrap_runtime as bootstrap

    columns = [
        {"table": table, "name": name, "type": type_name}
        for table, contract in bootstrap._OWNED_TABLE_CONTRACTS.items()
        if table in {"event_placement", "sessions", "incremental_copy_manifest"}
        for name, type_name in contract.items()
    ]
    responses = iter([
        b'{"data":[{"rows":1}]}',
        b'{"data":[{"name":"event_placement","engine":"MergeTree","create_table_query":"placement"},{"name":"sessions","engine":"MergeTree","create_table_query":"sessions"},{"name":"incremental_copy_manifest","engine":"MergeTree","create_table_query":"manifest"}]}',
        json.dumps({"data": columns}).encode("utf-8"),
        b'{"data":[{"rows":0}]}',
        b'{"data":[{"rows":0}]}',
        b'{"data":[{"rows":0}]}',
    ])
    monkeypatch.setattr(bootstrap, "_http_query", lambda *_args, **_kwargs: next(responses))

    preflight = bootstrap.preflight_target(8123)

    assert preflight["status"] == "empty"
    assert preflight["tables"] == [
        {"name": "event_placement", "rows": 0},
        {"name": "incremental_copy_manifest", "rows": 0},
        {"name": "sessions", "rows": 0},
    ]


def test_bootstrap_exact_recovery_rejects_nonempty_base_sessions(monkeypatch) -> None:
    from server.sli.storage import warm_tier_bootstrap_runtime as bootstrap

    frozen = {"rows": 1, "event_ids": [1], "identity_sha256": "a" * 64}

    def rows(_port: int, query: str):
        if "FROM system.tables" in query:
            return [
                {"name": "event_placement", "engine": "MergeTree"},
                {"name": "sessions", "engine": "MergeTree"},
            ]
        if "FROM system.columns" in query:
            return [
                {"table": table, "name": name, "type": type_name}
                for table in ("event_placement", "sessions")
                for name, type_name in bootstrap._OWNED_TABLE_CONTRACTS[table].items()
            ]
        if "FROM system.databases" in query:
            return []
        if "FROM sli_warm.sessions" in query:
            return [{"rows": 1}]
        raise AssertionError(query)

    monkeypatch.setattr(bootstrap, "_json_rows", rows)

    with pytest.raises(RuntimeError, match="warm_bootstrap_target_foreign_session_rows"):
        bootstrap._preflight_exact_recovery_target(8123, frozen)


def test_bootstrap_allows_only_exact_complete_placement_recovery(monkeypatch, tmp_path: Path) -> None:
    from contextlib import contextmanager
    from server.sli.storage import warm_tier_bootstrap_runtime as bootstrap

    plan = {"package_type": "WARM_TIER_INCREMENTAL_PLAN", "contract_version": 2, "bootstrap": {"contract": "sli.warm-tier-bootstrap.v1", "plan_digest": ""}}
    plan["bootstrap"]["plan_digest"] = bootstrap.plan_digest(plan)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    calls: list[str] = []
    monkeypatch.setattr(bootstrap, "EVIDENCE_ROOT", tmp_path)
    monkeypatch.setattr(bootstrap.copy_runtime, "validate_plan", lambda _plan: {"rows": 2, "event_ids": [1, 2], "identity_sha256": "a" * 64})
    monkeypatch.setattr(bootstrap, "preflight_target", lambda _port: (_ for _ in ()).throw(RuntimeError("warm_bootstrap_target_occupied")))
    monkeypatch.setattr(bootstrap, "_preflight_exact_recovery_target", lambda _port, _frozen: {"status": "exact_recovery"})
    @contextmanager
    def lock_free(*_args):
        yield True
    monkeypatch.setattr(bootstrap, "session_advisory_lock", lock_free)
    monkeypatch.setattr(bootstrap, "initialize_empty_target", lambda _port: calls.append("initialize"))
    monkeypatch.setattr(bootstrap.copy_runtime, "execute_and_record", lambda *_args, **_kwargs: {"status": "copied_and_verified", "safety": {}})

    result = bootstrap.execute_bootstrap(
        plan_path, confirmation=plan["bootstrap"]["plan_digest"], execute=True, port=8123,
    )

    assert calls == []
    assert result["bootstrap"]["target_preflight"]["status"] == "exact_recovery"


def test_absent_target_candidate_scan_never_queries_warm_event_placement(monkeypatch) -> None:
    from server.sli.storage import warm_tier_bootstrap_runtime as bootstrap

    checked = datetime(2026, 8, 2, tzinfo=timezone.utc)
    queried: list[str] = []

    class Cursor:
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def execute(self, *_args): return None
        def fetchone(self): return {"checked_at_utc": checked}

    class Connection:
        def execute(self, *_args): return None
        def cursor(self): return Cursor()
        def __enter__(self): return self
        def __exit__(self, *_args): return None

    monkeypatch.setattr(bootstrap, "preflight_target", lambda _port: {
        "status": "empty", "database_exists": False, "tables": [],
        "schema_fingerprint": None,
    })
    monkeypatch.setattr(bootstrap, "_connect", lambda: Connection())
    monkeypatch.setattr(bootstrap.planner, "load_storage_policy", lambda: type("P", (), {
        "db_retention_days": 7, "warm_retention_days": 365,
        "archive_auto_delete_enabled": False,
    })())
    monkeypatch.setattr(bootstrap.planner, "_source_summary", lambda *_args, **_kwargs: {
        "source_rows": 1, "source_max_event_id": 10, "appended_rows": 1,
        "eligible_rows": 1, "checked_at_utc": checked,
    })
    pages = iter([[_row(10, 1, checked - timedelta(days=20))], []])
    monkeypatch.setattr(bootstrap.planner, "_candidate_page", lambda *_args, **_kwargs: next(pages))
    monkeypatch.setattr(bootstrap.planner, "_http_query", lambda _port, query, *_args, **_kwargs: queried.append(query) or b"")
    monkeypatch.setattr(bootstrap.planner, "_next_durable_descriptor_batch", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("bootstrap_must_not_select_durable_descriptors")))
    monkeypatch.setattr(bootstrap.planner, "_archive_coverage", lambda *_args, **_kwargs: {"missing": 0, "missing_ids": []})

    plan = bootstrap.build_bootstrap_plan(batch_limit=10, scan_limit=20, port=8123)

    assert plan["planned_batch"]["event_ids"] == [10]
    assert not any("event_placement" in query for query in queried)


def test_bootstrap_recovery_allows_exact_session_rows_but_rejects_foreign_session_batch(monkeypatch) -> None:
    from server.sli.storage import warm_tier_bootstrap_runtime as bootstrap

    frozen = {"rows": 2, "event_ids": [1, 2], "identity_sha256": "a" * 64}
    known_tables = [
        {"name": "event_placement", "engine": "MergeTree"},
        {"name": "incremental_copy_manifest", "engine": "MergeTree"},
        {"name": "session_lifecycle_revisions", "engine": "MergeTree"},
        {"name": "event_session_placement_revisions", "engine": "MergeTree"},
        {"name": "authentication_session_derived_outputs", "engine": "MergeTree"},
    ] + [
        {
            "name": name, "engine": "View", "as_select": definition,
        }
        for name, definition in bootstrap._owned_view_contracts().items()
    ]

    def exact_rows(_port: int, query: str):
        if "FROM system.tables" in query and "ORDER BY name" in query:
            return known_tables
        if "FROM system.columns" in query:
            data_names = {
                row["name"] for row in known_tables if row["engine"] == "MergeTree"
            }
            return [
                {"table": table, "name": name, "type": type_name}
                for table in data_names
                for name, type_name in bootstrap._OWNED_TABLE_CONTRACTS[table].items()
            ]
        if "FROM system.databases" in query:
            return []
        if "FROM sli_warm.event_placement" in query:
            return [{"total_rows": 2, "matching_rows": 2}]
        if "incremental_copy_manifest" in query and "system.tables" in query:
            return [{"rows": 1}]
        if "FROM sli_warm.incremental_copy_manifest" in query:
            return [{"total_rows": 0, "matching_rows": 0}]
        if "authentication_session_derived_outputs" in query:
            return [{"total_rows": 0}]
        if "session_lifecycle_revisions" in query or "event_session_placement_revisions" in query:
            return [{"total_rows": 1, "matching_rows": 1}]
        raise AssertionError(query)

    monkeypatch.setattr(bootstrap, "_json_rows", exact_rows)
    monkeypatch.setattr(
        bootstrap, "_canonical_query", lambda _port, query: str(query),
    )
    assert bootstrap._preflight_exact_recovery_target(8123, frozen)["status"] == "exact_recovery"

    def foreign_rows(port: int, query: str):
        result = exact_rows(port, query)
        if "FROM sli_warm.session_lifecycle_revisions" in query:
            return [{"total_rows": 2, "matching_rows": 1}]
        return result

    monkeypatch.setattr(bootstrap, "_json_rows", foreign_rows)
    with pytest.raises(RuntimeError, match="warm_bootstrap_target_foreign_session_batch"):
        bootstrap._preflight_exact_recovery_target(8123, frozen)


def test_bootstrap_recovery_rejects_foreign_table_and_direct_output_or_staging_residue(monkeypatch) -> None:
    from server.sli.storage import warm_tier_bootstrap_runtime as bootstrap

    frozen = {"rows": 1, "event_ids": [1], "identity_sha256": "a" * 64}
    monkeypatch.setattr(bootstrap, "_json_rows", lambda _port, query: (
        [{"name": "foreign"}] if "FROM system.tables" in query else []
    ))
    with pytest.raises(RuntimeError, match="warm_bootstrap_target_foreign_tables"):
        bootstrap._preflight_exact_recovery_target(8123, frozen)

    def direct_rows(_port: int, query: str):
        if "FROM system.tables" in query and "ORDER BY name" in query:
            return [
                {"name": "event_placement", "engine": "MergeTree"},
                {"name": "authentication_session_derived_outputs", "engine": "MergeTree"},
            ]
        if "FROM system.columns" in query:
            return [
                {"table": table, "name": name, "type": type_name}
                for table in ("event_placement", "authentication_session_derived_outputs")
                for name, type_name in bootstrap._OWNED_TABLE_CONTRACTS[table].items()
            ]
        if "FROM system.databases" in query:
            return []
        if "FROM sli_warm.event_placement" in query:
            return [{"total_rows": 1, "matching_rows": 1}]
        if "authentication_session_derived_outputs" in query:
            return [{"total_rows": 1}]
        raise AssertionError(query)

    monkeypatch.setattr(bootstrap, "_json_rows", direct_rows)
    with pytest.raises(RuntimeError, match="warm_bootstrap_target_foreign_derived_output"):
        bootstrap._preflight_exact_recovery_target(8123, frozen)

    def stage_rows(_port: int, query: str):
        if "FROM system.tables" in query and "ORDER BY name" in query:
            return [{"name": "event_placement", "engine": "MergeTree"}]
        if "FROM system.columns" in query:
            return [
                {"table": "event_placement", "name": name, "type": type_name}
                for name, type_name in bootstrap._OWNED_TABLE_CONTRACTS["event_placement"].items()
            ]
        if "FROM system.databases" in query:
            return [{"name": "sli_warm_incremental_stale"}]
        raise AssertionError(query)

    monkeypatch.setattr(bootstrap, "_json_rows", stage_rows)
    with pytest.raises(RuntimeError, match="warm_bootstrap_staging_residue"):
        bootstrap._preflight_exact_recovery_target(8123, frozen)


def test_bootstrap_plan_reader_is_bounded(monkeypatch, tmp_path: Path) -> None:
    from server.sli.storage import warm_tier_bootstrap_runtime as bootstrap

    plan_path = tmp_path / "oversized-plan.json"
    plan_path.write_bytes(b" " * (bootstrap.copy_runtime.MAX_PLAN_JSON_BYTES + 1))
    monkeypatch.setattr(bootstrap.copy_runtime, "validate_plan", lambda *_args: pytest.fail("must_not_validate"))

    with pytest.raises(RuntimeError, match="warm_bootstrap_plan_too_large"):
        bootstrap._read_and_verify_bootstrap_plan(plan_path)
