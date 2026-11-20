from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import types

import pytest


def _module():
    path = Path("scripts/maintenance/semantic_dispatch_partition_recovery.py")
    spec = importlib.util.spec_from_file_location("semantic_dispatch_partition_recovery_maintenance", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_cli_refuses_invalid_confirmation_before_environment_or_write_connection(monkeypatch, tmp_path: Path) -> None:
    module = _module()
    plan = tmp_path / "plan.json"
    material = {"plan_version": "test"}
    digest = module._digest(material)
    plan.write_text(__import__("json").dumps({**material, "plan_digest": digest, "confirmation": "wrong"}), encoding="utf-8")
    calls: list[str] = []
    monkeypatch.setattr(module, "_load_main_environment", lambda: calls.append("environment"))
    monkeypatch.setattr(module, "_connect_admin", lambda: calls.append("write") or None)
    with pytest.raises(RuntimeError, match="confirmation"):
        module.load_apply_plan(plan, plan_digest=digest, confirmation="wrong")
    assert calls == []


def test_requeue_updates_only_the_exact_remaining_uuid_set() -> None:
    module = _module()
    executed: list[tuple[str, tuple[object, ...]]] = []

    class Cursor:
        rowcount = 2
        def execute(self, sql, params=()):
            executed.append((" ".join(sql.split()), tuple(params)))
        def fetchall(self):
            return [
                {"job_id": "10eac730-5285-5740-b605-577d3ef9f4c2"},
                {"job_id": "e24572a7-159d-517c-a284-a0eff96ac007"},
            ]

    module.PostgresRecoveryAdapter.requeue_with_cursor(
        Cursor(), ["10eac730-5285-5740-b605-577d3ef9f4c2", "e24572a7-159d-517c-a284-a0eff96ac007"]
    )
    sql, params = executed[0]
    assert "where job_id=any(%s::uuid[])" in sql
    assert "dispatch_status='quarantined'" in sql
    assert "dispatch_status='queued'" in sql
    assert "lease_token is null" in sql
    assert "lease_until is null" in sql
    assert "heartbeat_at is null" in sql
    assert "attempt_count=max_attempts" in sql
    assert "attempt_count=5" in sql
    assert "max_attempts=6" not in sql
    assert "dispatch_status='leased'" in sql
    assert "lease_until<=now()" in sql
    assert any("semantic_correlation_dispatch_terminal" in str(item) for item in params)
    assert "returning job_id" in sql
    assert params[0] == ["10eac730-5285-5740-b605-577d3ef9f4c2", "e24572a7-159d-517c-a284-a0eff96ac007"]
    assert "last_error_code=null" not in sql
    assert "last_error_detail=null" not in sql


def test_recovery_claim_is_exact_and_does_not_consume_an_attempt() -> None:
    module = _module()
    executed: list[tuple[str, tuple[object, ...]]] = []

    class Cursor:
        def execute(self, sql, params=()):
            executed.append((" ".join(sql.split()), tuple(params)))
        def fetchall(self):
            return [{
                "job_id": "10eac730-5285-5740-b605-577d3ef9f4c2",
                "lease_token": "lease", "attempt_count": 5, "max_attempts": 5,
            }]

    rows = module.claim_recovery_dispatch_jobs(
        Cursor(), limit=1,
        allowed_job_ids=["10eac730-5285-5740-b605-577d3ef9f4c2"],
        allowed_rule_identities=[(module.RULE_ID, module.RULE_VERSION, module.RULE_SHA256)],
    )

    sql, params = executed[0]
    assert len(rows) == 1
    assert "job.job_id=any(%s::uuid[])" in sql
    assert "attempt_count=5 and job.max_attempts=5" in sql
    assert "attempt_count=attempt_count+1" not in sql
    assert "last_error_code=null" not in sql
    assert "last_error_detail=null" not in sql
    assert params[0] == ["10eac730-5285-5740-b605-577d3ef9f4c2"]
    assert any("semantic_correlation_dispatch_terminal" in str(item) for item in params)


def test_recovery_completion_clears_preserved_error_atomically() -> None:
    module = _module()
    executed: list[tuple[str, tuple[object, ...]]] = []

    class Cursor:
        def execute(self, sql, params=()): executed.append((" ".join(sql.split()), tuple(params)))
        def fetchone(self): return {"job_id": "job-1"}

    module.complete_recovery_dispatch_job(Cursor(), job_id="job-1", lease_token="lease-1")
    sql, params = executed[0]
    assert "dispatch_status='completed'" in sql
    assert "last_error_code=null" in sql
    assert "last_error_detail=null" in sql
    assert "dispatch_status='leased'" in sql
    assert params == ("job-1", "lease-1")


def test_snapshot_reads_source_ids_from_normalized_events(monkeypatch) -> None:
    module = _module()
    executed: list[str] = []
    fetches = iter([[{
        "job_id": "10eac730-5285-5740-b605-577d3ef9f4c2",
        "source_event_id": 6943209,
        "semantic_contract_version": 1,
        "normalizer_id": "windows.named-eventdata",
        "normalizer_version": "1.4+identity-1.0",
    }], [{
        "source_event_ids": [6923513, 6943209],
        "candidate_key_hex": module._candidate_key_hex(
            "dispatch:5497fb27862a7026a64b5e77f41d8e0a3fa181d9429bffa34671b899eedebe23"
        ),
        "contract_exact": False,
        "repairable_contract_exact": True,
    }]])

    class Cursor:
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def execute(self, sql, _params=()): executed.append(" ".join(sql.split()))
        def fetchall(self): return next(fetches)

    class Connection:
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def cursor(self): return Cursor()

    monkeypatch.setattr(module, "_connect_admin", lambda: Connection())
    rows = module.PostgresRecoveryAdapter().snapshot()

    assert rows[0]["accepted_relations"] == []
    assert len(rows[0]["repairable_relations"]) == 1
    assert rows[0]["blocking_relations"] == []
    relation_sql = executed[-1]
    assert "array_agg(distinct normalized.source_event_id" in relation_sql
    assert "filter (where" in relation_sql
    assert "bool_or(normalized.source_event_id=%s)" in relation_sql
    assert "evidence.source_event_id" not in relation_sql
    assert "repairable_contract_exact" in relation_sql


def test_requeue_refuses_wrong_returned_uuid_set() -> None:
    module = _module()

    class Cursor:
        def execute(self, *_args, **_kwargs): return None
        def fetchall(self): return [{"job_id": "00000000-0000-0000-0000-000000000000"}]

    with pytest.raises(RuntimeError, match="requeue set changed"):
        module.PostgresRecoveryAdapter.requeue_with_cursor(
            Cursor(), ["10eac730-5285-5740-b605-577d3ef9f4c2"]
        )


def test_atomic_audit_is_secret_free_and_read_back(tmp_path: Path) -> None:
    module = _module()
    target = tmp_path / "audit.json"
    result = module.write_atomic_audit(target, {"status": "complete", "dsn": "postgres://secret@host/db"})
    assert result["status"] == "complete"
    assert "secret" not in target.read_text(encoding="utf-8")


def test_worker_guard_unavailable_fails_closed(monkeypatch) -> None:
    module = _module()

    class Conn:
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def cursor(self): return Cursor()
    class Cursor:
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def execute(self, *_args): return None
        def fetchone(self): return {"live": False}

    monkeypatch.setattr(module, "_connect_admin", lambda: Conn())
    fake_guard = types.SimpleNamespace(evaluate_cycle=lambda _workers: {
        "semantic": {"code": 1, "decision": "refused_db_unreachable"}
    })
    monkeypatch.setitem(sys.modules, "scripts.maintenance.worker_guard", fake_guard)
    assert module.PostgresRecoveryAdapter().worker_is_live() is True


def test_admin_connection_forwards_autocommit(monkeypatch) -> None:
    module = _module()
    l1 = types.ModuleType("scripts.maintenance.semantic_l1_shadow_control")
    l1._connect_admin = lambda **kwargs: kwargs
    monkeypatch.setitem(sys.modules, l1.__name__, l1)

    assert module._connect_admin(autocommit=True) == {"autocommit": True}

@pytest.mark.parametrize("raises", [False, True])
@pytest.mark.parametrize("ambient", [None, "ambient-dsn"])
def test_dispatch_uses_ephemeral_worker_dsn_and_always_restores_and_drops(monkeypatch, raises: bool, ambient: str | None) -> None:
    module = _module()
    l1 = types.ModuleType("scripts.maintenance.semantic_l1_shadow_control")
    runtime = types.ModuleType("server.sli.semantic.semantic_production_runtime")
    worker_connection = types.ModuleType("server.sli.semantic.semantic_worker_connection")
    worker_runtime = types.ModuleType("server.sli.semantic.semantic_worker_runtime")

    events: list[object] = []

    class Cursor:
        def __enter__(self): return self
        def __exit__(self, *_args): return None

    class Connection:
        def cursor(self): return Cursor()
        def __enter__(self): return self
        def __exit__(self, *_args): return None

    if ambient is None:
        monkeypatch.delenv("ADLOG_SEMANTIC_WORKER_DSN", raising=False)
    else:
        monkeypatch.setenv("ADLOG_SEMANTIC_WORKER_DSN", ambient)
    monkeypatch.setenv("ADLOG_SEMANTIC_RUNTIME_MODE", "findings-v1")
    monkeypatch.setenv("ADLOG_SEMANTIC_RISK_ENGINE_ENABLED", "1")
    monkeypatch.setenv("ADLOG_SEMANTIC_FINDING_CREATION_ENABLED", "1")
    monkeypatch.setattr(module, "_connect_admin", lambda **_kwargs: Connection())
    l1._create_ephemeral_login = lambda _cur: events.append("create") or ("adlog_semantic_l1_test", "secret-password")
    l1._worker_dsn = lambda **_kwargs: "ephemeral-dsn"
    l1._drop_ephemeral_login = lambda _cur, role: events.append(("drop", role))
    worker_connection.connect_semantic_worker = lambda: Connection()
    runtime.INVESTIGATION_MODE = "investigation-v1"
    runtime.prepare_production_connection = lambda _conn, **_kwargs: "settings"
    monkeypatch.setitem(sys.modules, l1.__name__, l1)
    monkeypatch.setitem(sys.modules, runtime.__name__, runtime)
    monkeypatch.setitem(sys.modules, worker_connection.__name__, worker_connection)
    monkeypatch.setitem(sys.modules, worker_runtime.__name__, worker_runtime)

    def process(_conn, **kwargs):
        assert __import__("os").environ["ADLOG_SEMANTIC_WORKER_DSN"] == "ephemeral-dsn"
        assert __import__("os").environ["ADLOG_SEMANTIC_RUNTIME_MODE"] == "investigation-v1"
        assert __import__("os").environ["ADLOG_SEMANTIC_RISK_ENGINE_ENABLED"] == "0"
        assert __import__("os").environ["ADLOG_SEMANTIC_FINDING_CREATION_ENABLED"] == "0"
        assert kwargs["archive"].__class__.__name__ == "TrapArchive"
        assert kwargs["allowed_job_ids"] == ["job-1"]
        if raises:
            raise RuntimeError("dispatch boom")
        return {"completed": 1, "failed": 0, "relations": 0}

    worker_runtime.process_semantic_dispatch = process
    scope = {"normalized_before": "2026-09-20T10:00:00+00:00", "allowed_job_ids": ["job-1"]}
    if raises:
        with pytest.raises(RuntimeError, match="dispatch boom"):
            module.PostgresRecoveryAdapter().dispatch(scope)
    else:
        assert module.PostgresRecoveryAdapter().dispatch(scope)["completed"] == 1
    if ambient is None:
        assert "ADLOG_SEMANTIC_WORKER_DSN" not in __import__("os").environ
    else:
        assert __import__("os").environ["ADLOG_SEMANTIC_WORKER_DSN"] == ambient
    assert __import__("os").environ["ADLOG_SEMANTIC_RUNTIME_MODE"] == "findings-v1"
    assert __import__("os").environ["ADLOG_SEMANTIC_RISK_ENGINE_ENABLED"] == "1"
    assert __import__("os").environ["ADLOG_SEMANTIC_FINDING_CREATION_ENABLED"] == "1"
    assert events == ["create", ("drop", "adlog_semantic_l1_test")]


def test_main_does_not_print_exception_message_or_secret(monkeypatch, capsys) -> None:
    module = _module()
    monkeypatch.setattr(sys, "argv", ["semantic_dispatch_partition_recovery.py", "plan"])
    monkeypatch.setattr(
        module,
        "run_plan",
        lambda _path: (_ for _ in ()).throw(RuntimeError("should-not-leak-marker")),
    )

    assert module.main() == 1
    captured = capsys.readouterr()
    assert "should-not-leak-marker" not in captured.err
    assert '"error_type": "RuntimeError"' in captured.err
