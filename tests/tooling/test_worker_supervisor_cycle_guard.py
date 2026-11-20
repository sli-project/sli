"""Supervisor no longer spawns a `worker_guard.py` subprocess per worker
every cycle: it calls the batched in-process guard cycle once and reads
each worker's decision back out of that one result.
"""
from __future__ import annotations

import io
import os
import sys
from types import SimpleNamespace

import pytest


def test_evaluate_once_calls_guard_cycle_exactly_once(monkeypatch) -> None:
    from scripts.maintenance import worker_supervisor

    monkeypatch.setattr(
        worker_supervisor, "verify_collection_identity",
        lambda: {"status": "ok"},
    )
    monkeypatch.setenv("ADLOG_STORAGE_LIFECYCLE_AUTOMATION_ENABLED", "1")
    monkeypatch.setenv(
        "ADLOG_STORAGE_LIFECYCLE_DELETE_ADMISSION",
        "APPLY-STAGE7-HOT-RETENTION-DELETE",
    )
    monkeypatch.setattr(worker_supervisor, "_start", lambda worker: {"started": False})
    monkeypatch.setattr(worker_supervisor.time, "sleep", lambda seconds: None)

    calls = {"count": 0}

    def fake_evaluate_cycle(workers):
        calls["count"] += 1
        return {
            worker: {"decision": "refused_worker_already_running", "code": 9}
            for worker in workers
        }

    monkeypatch.setattr(worker_supervisor.worker_guard, "evaluate_cycle", fake_evaluate_cycle)

    worker_supervisor.evaluate_once()

    assert calls["count"] == 1


def test_evaluate_once_does_not_spawn_a_guard_subprocess(monkeypatch) -> None:
    from scripts.maintenance import worker_supervisor

    monkeypatch.setattr(
        worker_supervisor, "verify_collection_identity",
        lambda: {"status": "ok"},
    )
    monkeypatch.setenv("ADLOG_STORAGE_LIFECYCLE_AUTOMATION_ENABLED", "1")
    monkeypatch.setenv(
        "ADLOG_STORAGE_LIFECYCLE_DELETE_ADMISSION",
        "APPLY-STAGE7-HOT-RETENTION-DELETE",
    )
    monkeypatch.setattr(worker_supervisor, "_start", lambda worker: {"started": False})
    monkeypatch.setattr(worker_supervisor.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(
        worker_supervisor.worker_guard, "evaluate_cycle",
        lambda workers: {w: {"decision": "safe_to_launch", "code": 0} for w in workers},
    )

    subprocess_run_calls = []
    monkeypatch.setattr(
        worker_supervisor.subprocess, "run",
        lambda *a, **k: subprocess_run_calls.append((a, k)),
    )

    worker_supervisor.evaluate_once()

    assert subprocess_run_calls == []


def test_semantic_requires_exact_production_admission(monkeypatch) -> None:
    from scripts.maintenance import worker_supervisor

    monkeypatch.delenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", raising=False)
    assert worker_supervisor.semantic_production_admitted() is False

    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "true")
    assert worker_supervisor.semantic_production_admitted() is True

    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "shadow")
    assert worker_supervisor.semantic_production_admitted() is False


def test_semantic_only_cycle_uses_only_semantic_guard_and_lifecycle(monkeypatch) -> None:
    from scripts.maintenance import worker_supervisor

    monkeypatch.setattr(
        worker_supervisor,
        "verify_collection_identity",
        lambda: (_ for _ in ()).throw(AssertionError("collection identity must not run")),
    )
    guard_workers: list[str] = []

    def evaluate_cycle(workers):
        guard_workers.extend(workers)
        return {
            worker: {"decision": "safe_to_launch", "code": 0}
            for worker in workers
        }

    monkeypatch.setattr(worker_supervisor.worker_guard, "evaluate_cycle", evaluate_cycle)
    lifecycle_workers: list[str] = []
    monkeypatch.setattr(
        worker_supervisor.control_center_lifecycle,
        "read_worker_intent",
        lambda worker: lifecycle_workers.append(worker) or None,
    )
    monkeypatch.setattr(worker_supervisor, "_start", lambda worker: {"started": False})

    report = worker_supervisor.evaluate_semantic_once()

    assert guard_workers == ["semantic"]
    assert lifecycle_workers == ["semantic"]
    assert report == {
        "workers": {
            "semantic": {
                "action": "started",
                "guard": "safe_to_launch",
                "started": False,
            }
        }
    }


def test_semantic_only_refuses_dpapi_load_failure_before_database_or_collection(monkeypatch) -> None:
    from scripts.maintenance import worker_supervisor

    monkeypatch.setattr(sys, "argv", ["worker_supervisor.py", "--semantic-only", "--once"])
    monkeypatch.setattr(
        worker_supervisor,
        "load_supervisor_environment",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("DPAPI unavailable")),
    )
    monkeypatch.setattr(
        worker_supervisor,
        "load_config",
        lambda: (_ for _ in ()).throw(AssertionError("database configuration must not run")),
    )
    monkeypatch.setattr(
        worker_supervisor,
        "verify_collection_identity",
        lambda: (_ for _ in ()).throw(AssertionError("collection identity must not run")),
    )

    assert worker_supervisor.main() == 1


@pytest.mark.parametrize(
    "environment",
    [
        {},
        {
            "ADLOG_SEMANTIC_PRODUCTION_ENABLED": "1",
            "ADLOG_SEMANTIC_RUNTIME_MODE": "facts-v1",
            "ADLOG_SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST": "a" * 64,
        },
        {
            "ADLOG_SEMANTIC_PRODUCTION_ENABLED": "1",
            "ADLOG_SEMANTIC_RUNTIME_MODE": "investigation-v1",
        },
        {
            "ADLOG_SEMANTIC_PRODUCTION_ENABLED": "1",
            "ADLOG_SEMANTIC_RUNTIME_MODE": "investigation-v1",
            "ADLOG_SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST": "invalid",
        },
    ],
)
def test_semantic_only_refuses_unadmitted_or_invalid_scope_before_database(monkeypatch, environment) -> None:
    from scripts.maintenance import worker_supervisor

    for name in (
        "ADLOG_SEMANTIC_PRODUCTION_ENABLED",
        "ADLOG_SEMANTIC_RUNTIME_MODE",
        "ADLOG_SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST",
    ):
        monkeypatch.delenv(name, raising=False)
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["worker_supervisor.py", "--semantic-only", "--once"])
    monkeypatch.setattr(
        worker_supervisor,
        "load_supervisor_environment",
        lambda **kwargs: {
            "keys": [
                "ADLOG_PG_DSN",
                "ADLOG_SEMANTIC_PRODUCTION_ENABLED",
                "ADLOG_SEMANTIC_RUNTIME_MODE",
                "ADLOG_SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST",
            ]
        },
    )
    monkeypatch.setattr(
        worker_supervisor,
        "load_config",
        lambda: (_ for _ in ()).throw(AssertionError("database configuration must not run")),
    )

    assert worker_supervisor.main() == 1


def test_semantic_only_refuses_inherited_scope_missing_from_canonical_profile(monkeypatch) -> None:
    from scripts.maintenance import worker_supervisor

    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
    monkeypatch.setenv("ADLOG_SEMANTIC_RUNTIME_MODE", "investigation-v1")
    monkeypatch.setenv("ADLOG_SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST", "a" * 64)
    monkeypatch.setattr(sys, "argv", ["worker_supervisor.py", "--semantic-only", "--once"])
    monkeypatch.setattr(
        worker_supervisor,
        "load_supervisor_environment",
        lambda **kwargs: {
            "keys": [
                "ADLOG_PG_DSN",
                "ADLOG_SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST",
            ]
        },
    )
    monkeypatch.setattr(
        worker_supervisor,
        "load_config",
        lambda: (_ for _ in ()).throw(AssertionError("database configuration must not run")),
    )

    assert worker_supervisor.main() == 1


def test_semantic_only_rejects_action_flags_before_provisioning(monkeypatch, capsys) -> None:
    from scripts.maintenance import worker_supervisor

    monkeypatch.setattr(
        sys,
        "argv",
        ["worker_supervisor.py", "--semantic-only", "--once", "--provision-environment"],
    )
    monkeypatch.setattr(
        worker_supervisor,
        "provision_supervisor_environment",
        lambda: (_ for _ in ()).throw(AssertionError("provisioning must not run")),
    )

    assert worker_supervisor.main() == 2
    assert "semantic_only_conflicts_with_action_flags" in capsys.readouterr().out


def test_semantic_only_main_uses_semantic_cycle_and_supervisor_lock(monkeypatch) -> None:
    from scripts.maintenance import worker_supervisor

    canonical_values = {
        "ADLOG_PG_DSN": "postgresql://semantic-test",
        "ADLOG_SEMANTIC_PRODUCTION_ENABLED": "1",
        "ADLOG_SEMANTIC_RUNTIME_MODE": "investigation-v1",
        "ADLOG_SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST": "a" * 64,
    }
    monkeypatch.setattr(sys, "argv", ["worker_supervisor.py", "--semantic-only", "--once"])

    def load_environment(**kwargs):
        for name, value in canonical_values.items():
            monkeypatch.setenv(name, value)
        return {"keys": sorted(canonical_values)}

    monkeypatch.setattr(worker_supervisor, "load_supervisor_environment", load_environment)
    monkeypatch.setattr(
        worker_supervisor,
        "verify_collection_identity",
        lambda: (_ for _ in ()).throw(AssertionError("collection identity must not run")),
    )
    monkeypatch.setattr(
        worker_supervisor,
        "evaluate_once",
        lambda: (_ for _ in ()).throw(AssertionError("ordinary cycle must not run")),
    )

    guard_workers: list[list[str]] = []
    monkeypatch.setattr(
        worker_supervisor.worker_guard,
        "evaluate_cycle",
        lambda workers: guard_workers.append(list(workers)) or {
            "semantic": {"decision": "already_running", "code": 9}
        },
    )
    lifecycle_workers: list[str] = []
    monkeypatch.setattr(
        worker_supervisor.control_center_lifecycle,
        "read_worker_intent",
        lambda worker: lifecycle_workers.append(worker) or None,
    )

    semantic_cycle_calls: list[bool] = []
    original_semantic_cycle = worker_supervisor.evaluate_semantic_once

    def evaluate_semantic_once():
        semantic_cycle_calls.append(True)
        return original_semantic_cycle()

    monkeypatch.setattr(worker_supervisor, "evaluate_semantic_once", evaluate_semantic_once)

    queries: list[str] = []

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, query, _params):
            queries.append(query)

        def fetchone(self):
            return (True,)

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def cursor(self):
            return Cursor()

    connect_calls: list[tuple[object, dict[str, object]]] = []

    def connect(*args, **kwargs):
        connect_calls.append((args, kwargs))
        return Connection()

    monkeypatch.setitem(sys.modules, "psycopg", SimpleNamespace(connect=connect))

    assert worker_supervisor.main() == 0
    assert semantic_cycle_calls == [True]
    assert guard_workers == [["semantic"]]
    assert lifecycle_workers == ["semantic"]
    assert len(connect_calls) == 1
    assert "pg_try_advisory_lock" in queries[0]
    assert "pg_advisory_unlock" in queries[-1]


def test_semantic_only_once_can_use_explicit_main_profile_and_semantic_interpreter(
    monkeypatch, tmp_path,
) -> None:
    """A worktree probe may use only the explicit canonical Main runtime inputs."""
    from scripts.maintenance import worker_supervisor

    # Main is resolved by the code (checkout layout dependent); pin it to a fake Main root
    # holding the runtime files so the test does not depend on where the worktree lives.
    main_root = tmp_path
    monkeypatch.setattr(worker_supervisor, "_main_checkout_root", lambda: main_root)
    profile = main_root / "data" / "runtime" / "worker-supervisor.env.dpapi"
    interpreter = main_root / ".venv" / "Scripts" / "python.exe"
    for runtime_file in (profile, interpreter):
        runtime_file.parent.mkdir(parents=True, exist_ok=True)
        runtime_file.write_bytes(b"")
    canonical_values = {
        "ADLOG_PG_DSN": "postgresql://semantic-test",
        "ADLOG_SEMANTIC_PRODUCTION_ENABLED": "1",
        "ADLOG_SEMANTIC_RUNTIME_MODE": "investigation-v1",
        "ADLOG_SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST": "a" * 64,
    }
    loaded: list[dict[str, object]] = []

    def load_environment(**kwargs):
        loaded.append(kwargs)
        for name, value in canonical_values.items():
            monkeypatch.setenv(name, value)
        return {"keys": sorted(canonical_values)}

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "worker_supervisor.py", "--semantic-only", "--once",
            "--environment-file", str(profile),
            "--semantic-python", str(interpreter),
        ],
    )
    monkeypatch.setattr(worker_supervisor, "load_supervisor_environment", load_environment)
    monkeypatch.setattr(
        worker_supervisor.control_center_lifecycle,
        "read_worker_intent",
        lambda worker: None,
    )
    monkeypatch.setattr(
        worker_supervisor.worker_guard,
        "evaluate_cycle",
        lambda workers: {"semantic": {"decision": "safe_to_launch", "code": 0}},
    )
    monkeypatch.setattr(worker_supervisor.Path, "open", lambda *_args, **_kwargs: io.StringIO())
    launched: list[list[str]] = []
    monkeypatch.setattr(
        worker_supervisor.subprocess,
        "Popen",
        lambda args, **_kwargs: launched.append(args) or SimpleNamespace(pid=17),
    )

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, *_args):
            return None

        def fetchone(self):
            return (True,)

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def cursor(self):
            return Cursor()

    monkeypatch.setitem(sys.modules, "psycopg", SimpleNamespace(connect=lambda *_args, **_kwargs: Connection()))

    assert worker_supervisor.main() == 0
    assert loaded == [{"path": profile.resolve(), "override_existing": True}]
    assert launched[0][0] == str(interpreter.resolve())


def test_explicit_semantic_runtime_paths_are_rejected_outside_semantic_once(monkeypatch, capsys) -> None:
    from scripts.maintenance import worker_supervisor

    profile = worker_supervisor.ROOT.parents[1] / "data" / "runtime" / "worker-supervisor.env.dpapi"
    monkeypatch.setattr(
        sys,
        "argv",
        ["worker_supervisor.py", "--once", "--environment-file", str(profile)],
    )
    monkeypatch.setattr(
        worker_supervisor,
        "load_supervisor_environment",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("profile must not load")),
    )

    assert worker_supervisor.main() == 2
    assert "semantic_runtime_path_requires_semantic_only_once" in capsys.readouterr().out


def test_semantic_only_once_rejects_a_non_main_interpreter_before_profile_load(monkeypatch, tmp_path) -> None:
    from scripts.maintenance import worker_supervisor

    foreign_interpreter = tmp_path / "python.exe"
    foreign_interpreter.write_text("not an interpreter", encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "worker_supervisor.py", "--semantic-only", "--once",
            "--semantic-python", str(foreign_interpreter),
        ],
    )
    monkeypatch.setattr(
        worker_supervisor,
        "load_supervisor_environment",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("profile must not load")),
    )

    assert worker_supervisor.main() == 1


def test_semantic_only_guard_failure_redacts_raw_payload_from_report_and_log(monkeypatch) -> None:
    from scripts.maintenance import worker_supervisor

    leaked_dsn = "FAKE-PRIVATE-CONNECTION-TOKEN-DO-NOT-LOG"
    monkeypatch.setattr(
        worker_supervisor.worker_guard,
        "evaluate_cycle",
        lambda workers: {
            "semantic": {
                "decision": "guard_database_error",
                "code": 1,
                "reason_code": "guard_database_error",
                "error": leaked_dsn,
            }
        },
    )
    monkeypatch.setattr(worker_supervisor.control_center_lifecycle, "read_worker_intent", lambda worker: None)
    log_calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
    monkeypatch.setattr(
        worker_supervisor,
        "_log",
        lambda *args, **kwargs: log_calls.append((args, kwargs)),
    )

    report = worker_supervisor.evaluate_semantic_once()

    assert leaked_dsn not in __import__("json").dumps(report)
    assert leaked_dsn not in __import__("json").dumps(log_calls)
