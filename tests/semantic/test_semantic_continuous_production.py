from __future__ import annotations

from dataclasses import replace
from contextlib import contextmanager, nullcontext
from pathlib import Path
from types import SimpleNamespace
import sys
import pytest

from server.sli.semantic.semantic_processing import SemanticFeatureSettings


def _enabled_settings() -> SemanticFeatureSettings:
    return SemanticFeatureSettings(
        normalization_enabled=True,
        assembly_enabled=True,
        directory_state_enabled=False,
        correlation_enabled=True,
        risk_engine_enabled=True,
        finding_creation_enabled=True,
    )


def _facts_settings() -> SemanticFeatureSettings:
    return SemanticFeatureSettings(
        normalization_enabled=True,
        assembly_enabled=True,
        directory_state_enabled=False,
        correlation_enabled=False,
        risk_engine_enabled=False,
        finding_creation_enabled=False,
    )


def _investigation_settings() -> SemanticFeatureSettings:
    return SemanticFeatureSettings(
        normalization_enabled=True,
        assembly_enabled=True,
        directory_state_enabled=False,
        correlation_enabled=True,
        risk_engine_enabled=False,
        finding_creation_enabled=False,
    )


def _findings_guard(**overrides: object) -> dict[str, object]:
    guard: dict[str, object] = {
        "processor_version_gate_schema_ready": True,
        "investigation_rule_lock_schema_ready": True,
        "investigation_rule_lock_capability_ready": True,
        "schema_ready": True,
        "enabled_policies": ["l1-audit-policy-changed:2"],
        "test_policy_exists": False,
    }
    guard.update(overrides)
    return guard


def _configure_stages(monkeypatch, *, facts=False):
    from server.sli.semantic import semantic_production_runtime as runtime
    monkeypatch.setattr(runtime, "run_default_detections", lambda _: {"sources": 0, "jobs": 0, "failed": 0})
    monkeypatch.setattr(runtime, "run_sigma_detections", lambda _: {"policies": 0, "jobs": 0, "failed": 0})
    for stage in ("NORMALIZATION", "ASSEMBLY", "CORRELATION", "RISK_ENGINE", "FINDING_CREATION"):
        enabled = not facts or stage in {"NORMALIZATION", "ASSEMBLY"}
        monkeypatch.setenv(f"ADLOG_SEMANTIC_{stage}_ENABLED", "1" if enabled else "0")
    monkeypatch.setenv("ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED", "0")


class _Cursor:
    def __init__(self, row: dict[str, object], queries: list[str] | None = None) -> None:
        self.row = row
        self.queries = queries

    def __enter__(self) -> "_Cursor":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, _query: str, _params: object = None) -> None:
        if self.queries is not None:
            self.queries.append(_query)

    def fetchone(self) -> dict[str, object]:
        return self.row


class _Connection:
    def __init__(self, row: dict[str, object]) -> None:
        self.row = row
        self.commits = 0

    def cursor(self) -> _Cursor:
        return _Cursor(self.row)

    def commit(self) -> None:
        self.commits += 1


def test_production_scope_accepts_only_the_accepted_enabled_policy(monkeypatch) -> None:
    from server.sli.semantic import semantic_production_runtime as runtime

    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
    monkeypatch.setattr(
        runtime.SemanticFeatureSettings,
        "from_env",
        classmethod(lambda cls: _enabled_settings()),
    )
    conn = _Connection(_findings_guard())

    settings = runtime.prepare_production_connection(conn)

    assert settings == _enabled_settings()
    assert conn.commits == 1


def test_facts_scope_accepts_normalization_and_assembly_only(monkeypatch) -> None:
    from server.sli.semantic import semantic_production_runtime as runtime

    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
    monkeypatch.setenv("ADLOG_SEMANTIC_RUNTIME_MODE", "facts-v1")
    monkeypatch.setattr(
        runtime.SemanticFeatureSettings,
        "from_env",
        classmethod(lambda cls: _facts_settings()),
    )
    conn = _Connection(
        {
            "facts_schema_ready": True,
            "processor_version_gate_schema_ready": True,
            "facts_capability_ready": True,
            "schema_ready": False,
            "enabled_policies": [],
            "test_policy_exists": False,
        }
    )

    settings = runtime.prepare_production_connection(conn)

    assert settings == _facts_settings()
    assert conn.commits == 1


def test_investigation_scope_accepts_normalization_actions_and_relations(monkeypatch) -> None:
    from server.sli.semantic import semantic_production_runtime as runtime

    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
    monkeypatch.setenv("ADLOG_SEMANTIC_RUNTIME_MODE", "investigation-v1")
    monkeypatch.setattr(
        runtime.SemanticFeatureSettings,
        "from_env",
        classmethod(lambda cls: _investigation_settings()),
    )
    conn = _Connection(
        {
            "facts_schema_ready": True,
            "processor_version_gate_schema_ready": True,
            "facts_capability_ready": True,
            "investigation_schema_ready": True,
            "investigation_capability_ready": True,
            "investigation_rule_lock_schema_ready": True,
            "investigation_rule_lock_capability_ready": True,
            "investigation_context_schema_ready": True,
            "investigation_context_capability_ready": True,
        }
    )

    settings = runtime.prepare_production_connection(conn)

    assert settings == _investigation_settings()
    assert conn.commits == 1


@pytest.mark.parametrize(
    ("missing_capability", "message"),
    (
        ("investigation_rule_lock_schema_ready", "schema markers"),
        ("investigation_rule_lock_capability_ready", "least-privilege capability"),
    ),
)
def test_investigation_scope_rejects_missing_rule_lock_preflight(
    monkeypatch,
    missing_capability: str,
    message: str,
) -> None:
    from server.sli.semantic import semantic_production_runtime as runtime

    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
    monkeypatch.setenv("ADLOG_SEMANTIC_RUNTIME_MODE", "investigation-v1")
    monkeypatch.setattr(
        runtime.SemanticFeatureSettings,
        "from_env",
        classmethod(lambda cls: _investigation_settings()),
    )
    guard = {
        "facts_schema_ready": True,
        "processor_version_gate_schema_ready": True,
        "facts_capability_ready": True,
        "investigation_schema_ready": True,
        "investigation_capability_ready": True,
        "investigation_rule_lock_schema_ready": True,
        "investigation_rule_lock_capability_ready": True,
        "investigation_context_schema_ready": True,
        "investigation_context_capability_ready": True,
    }
    guard[missing_capability] = False
    conn = _Connection(guard)

    with pytest.raises(RuntimeError, match=message):
        runtime.prepare_production_connection(conn)


@pytest.mark.parametrize(
    ("missing_capability", "message"),
    (
        ("investigation_rule_lock_schema_ready", "schema markers 55 and 141"),
        ("investigation_rule_lock_capability_ready", "rule-lock capability"),
    ),
)
def test_findings_scope_rejects_missing_rule_lock_preflight(
    monkeypatch,
    missing_capability: str,
    message: str,
) -> None:
    from server.sli.semantic import semantic_production_runtime as runtime

    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
    monkeypatch.setenv("ADLOG_SEMANTIC_RUNTIME_MODE", "findings-v1")
    monkeypatch.setattr(
        runtime.SemanticFeatureSettings,
        "from_env",
        classmethod(lambda cls: _enabled_settings()),
    )
    guard = _findings_guard()
    guard[missing_capability] = False

    with pytest.raises(RuntimeError, match=message):
        runtime.prepare_production_connection(_Connection(guard))


def test_rule_lock_preflight_rejects_grant_option_in_sql_contract() -> None:
    source = Path("server/sli/semantic/semantic_production_runtime.py").read_text(
        encoding="utf-8"
    )

    assert "'UPDATE WITH GRANT OPTION'" in source


@pytest.mark.parametrize(
    ("settings", "message"),
    [
        (
            replace(_investigation_settings(), correlation_enabled=False),
            "investigation mode requires normalization, assembly and correlation",
        ),
        (
            replace(_investigation_settings(), risk_engine_enabled=True),
            "investigation mode forbids risk evaluation",
        ),
        (
            replace(_investigation_settings(), finding_creation_enabled=True),
            "investigation mode forbids finding creation",
        ),
    ],
)
def test_investigation_scope_rejects_risk_or_incomplete_chain(
    monkeypatch,
    settings: SemanticFeatureSettings,
    message: str,
) -> None:
    from server.sli.semantic import semantic_production_runtime as runtime

    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
    monkeypatch.setenv("ADLOG_SEMANTIC_RUNTIME_MODE", "investigation-v1")
    monkeypatch.setattr(
        runtime.SemanticFeatureSettings,
        "from_env",
        classmethod(lambda cls: settings),
    )

    with pytest.raises(RuntimeError, match=message):
        runtime.prepare_production_connection(_Connection({}))


@pytest.mark.parametrize(
    ("mode", "settings", "message"),
    [
        ("unknown-v1", _facts_settings(), "semantic runtime mode is unsupported"),
        ("facts-v1", _enabled_settings(), "facts mode forbids correlation"),
        ("facts-v1", SemanticFeatureSettings(normalization_enabled=True), "facts mode requires normalization and assembly"),
    ],
)
def test_runtime_scope_rejects_unknown_or_inconsistent_mode_before_claim(
    monkeypatch,
    mode: str,
    settings: SemanticFeatureSettings,
    message: str,
) -> None:
    from server.sli.semantic import semantic_production_runtime as runtime

    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
    monkeypatch.setenv("ADLOG_SEMANTIC_RUNTIME_MODE", mode)
    monkeypatch.setattr(
        runtime.SemanticFeatureSettings,
        "from_env",
        classmethod(lambda cls: settings),
    )
    conn = _Connection({})

    with pytest.raises(RuntimeError, match=message):
        runtime.prepare_production_connection(conn)

    assert conn.commits == 0


def test_runtime_mode_refuses_facts_when_production_admission_is_off() -> None:
    from server.sli.semantic import semantic_production_runtime as runtime

    with pytest.raises(RuntimeError, match="semantic production admission is required"):
        runtime.semantic_runtime_mode_from_env(
            {
                "ADLOG_SEMANTIC_PRODUCTION_ENABLED": "0",
                "ADLOG_SEMANTIC_RUNTIME_MODE": "facts-v1",
            }
        )


def test_runtime_rejects_unknown_mode_before_opening_a_connection(monkeypatch) -> None:
    from server.sli.semantic import semantic_production_runtime as runtime

    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
    monkeypatch.setenv("ADLOG_SEMANTIC_RUNTIME_MODE", "unknown-v1")

    with pytest.raises(RuntimeError, match="semantic runtime mode is unsupported"):
        runtime.run_once(
            limit=1,
            connect_factory=lambda: (_ for _ in ()).throw(
                AssertionError("unsupported mode must not connect")
            ),
            archive=object(),
        )


def test_production_scope_rejects_any_unexpected_enabled_policy(monkeypatch) -> None:
    from server.sli.semantic import semantic_production_runtime as runtime

    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
    monkeypatch.setattr(
        runtime.SemanticFeatureSettings,
        "from_env",
        classmethod(lambda cls: _enabled_settings()),
    )
    conn = _Connection(_findings_guard(enabled_policies=[
        "l1-audit-policy-changed:2",
        "l1-eventlog-cleared:2",
    ]))

    with pytest.raises(RuntimeError, match="enabled policy set differs"):
        runtime.prepare_production_connection(conn)

    assert conn.commits == 0


@pytest.mark.parametrize(
    ("settings", "row", "message"),
    [
        (
            SemanticFeatureSettings(),
            _findings_guard(),
            "complete semantic production feature chain is required",
        ),
        (
            replace(_enabled_settings(), directory_state_enabled=True),
            _findings_guard(),
            "directory-state persistence is not accepted",
        ),
        (
            _enabled_settings(),
            _findings_guard(schema_ready=False),
            "schema markers 55 and 141 are required",
        ),
        (
            _enabled_settings(),
            _findings_guard(test_policy_exists=True),
            "refuses TEST policy",
        ),
    ],
)
def test_production_scope_rejects_incomplete_or_mixed_scope(
    monkeypatch,
    settings: SemanticFeatureSettings,
    row: dict[str, object],
    message: str,
) -> None:
    from server.sli.semantic import semantic_production_runtime as runtime

    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
    monkeypatch.setattr(
        runtime.SemanticFeatureSettings,
        "from_env",
        classmethod(lambda cls: settings),
    )
    conn = _Connection(row)

    with pytest.raises(RuntimeError, match=message):
        runtime.prepare_production_connection(conn)

    assert conn.commits == 0


class _Transaction:
    def __init__(self, conn) -> None:
        self.conn = conn

    def __enter__(self) -> "_Transaction":
        self.conn.info.transaction_status = 2
        return self

    def __exit__(self, *_args: object) -> None:
        self.conn.info.transaction_status = 0
        return None


class _RuntimeConnection:
    def __init__(self) -> None:
        self.closed = False
        self.info = SimpleNamespace(transaction_status=0)
        self.queries: list[str] = []

    def cursor(self) -> _Cursor:
        return _Cursor({}, self.queries)

    def transaction(self) -> _Transaction:
        return _Transaction(self)

    def close(self) -> None:
        self.closed = True


def test_production_cycle_publishes_enabled_result(monkeypatch) -> None:
    _configure_stages(monkeypatch)
    from server.sli.semantic import semantic_production_runtime as runtime

    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
    conn = _RuntimeConnection()
    work = SimpleNamespace(evaluation_mode="enabled")
    result = SimpleNamespace(evaluation_mode="enabled", finding_created=True)
    claims = [
        [{
            "job_id": "job-1",
            "lease_token": "lease-1",
            "attempt_count": 1,
            "max_attempts": 3,
        }],
        [],
    ]
    create_finding: list[bool] = []
    monkeypatch.setattr(
        runtime,
        "prepare_production_connection",
        lambda actual, **_kwargs: _enabled_settings(),
    )
    monkeypatch.setattr(
        runtime,
        "process_semantic_outbox",
        lambda *_args, **_kwargs: {"completed": 1, "failed": 0},
    )
    monkeypatch.setattr(
        runtime,
        "process_semantic_dispatch",
        lambda *_args, **_kwargs: {"completed": 0, "failed": 0},
    )
    monkeypatch.setattr(
        runtime,
        "enqueue_risk_backlog",
        lambda *_args, **_kwargs: ["job-1"],
    )
    monkeypatch.setattr(
        runtime,
        "claim_risk_evaluation_jobs",
        lambda *_args, **_kwargs: claims.pop(0),
    )
    monkeypatch.setattr(
        runtime,
        "load_risk_evaluation_work_item",
        lambda *_args, **_kwargs: work,
    )

    def execute(*_args, **kwargs):
        create_finding.append(bool(kwargs["create_finding"]))
        return result

    monkeypatch.setattr(runtime, "execute_risk_evaluation", execute)

    cycle = runtime.run_once(
        limit=1,
        connect_factory=lambda: conn,
        archive=object(),
    )

    assert cycle["status"] == "ok"
    assert cycle["modes"] == {"shadow": 0, "enabled": 1}
    assert cycle["findings_created"] == 1
    assert create_finding == [True]
    assert conn.queries.count("select expire_semantic_suppressions_v160()") == 1
    assert sum("semantic_policy_mode_v160" in query for query in conn.queries) == 1
    assert conn.closed is True


@pytest.mark.parametrize('stopping_stage', ['processing', 'dispatch', 'detections', 'sigma', 'risk'])
def test_sigterm_finishes_current_stage_without_starting_next(monkeypatch, stopping_stage):
    import signal
    from server.sli.ops import shutdown
    from server.sli.semantic import semantic_production_runtime as runtime

    _configure_stages(monkeypatch)
    monkeypatch.setenv('ADLOG_SEMANTIC_PRODUCTION_ENABLED', '1')
    conn = _RuntimeConnection()
    calls = []

    def stage(name, result):
        def execute(*args, **kwargs):
            calls.append(name)
            if name == stopping_stage:
                signal.raise_signal(signal.SIGTERM)
            return result
        return execute

    monkeypatch.setattr(runtime, 'prepare_production_connection', lambda *a, **kw: _enabled_settings())
    for name, attr in [('processing', 'process_semantic_outbox'), ('dispatch', 'process_semantic_dispatch'),
                       ('detections', 'run_default_detections'), ('sigma', 'run_sigma_detections')]:
        monkeypatch.setattr(runtime, attr, stage(name, {'completed': 0, 'jobs': 0, 'failed': 0}))
    monkeypatch.setattr(runtime, 'enqueue_risk_backlog', lambda *a, **kw: [])
    monkeypatch.setattr(runtime, 'claim_risk_evaluation_jobs', lambda *a, **kw: [{
        'job_id': 'job-1', 'lease_token': 'lease', 'attempt_count': 1, 'max_attempts': 3}])
    monkeypatch.setattr(runtime, 'load_risk_evaluation_work_item', lambda *a, **kw: SimpleNamespace(evaluation_mode='enabled'))
    monkeypatch.setattr(runtime, 'execute_risk_evaluation', stage('risk', SimpleNamespace(
        evaluation_mode='enabled', finding_created=True)))
    with shutdown.graceful_shutdown():
        cycle = runtime.run_once(limit=128, connect_factory=lambda: conn, archive=object())
    order = ['processing', 'dispatch', 'detections', 'sigma', 'risk']
    assert calls == order[:order.index(stopping_stage) + 1]
    assert cycle['failed'] == 0 and conn.closed
    assert cycle['findings_created'] == (1 if stopping_stage == 'risk' else 0)


@pytest.mark.parametrize("limit,expected", [(1, 1), (7, 7), (40, 16), (10000, 16)])
def test_risk_portion_is_bounded_without_reducing_normalization(monkeypatch, limit, expected):
    _configure_stages(monkeypatch)
    from server.sli.semantic import semantic_production_runtime as runtime

    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
    conn = _RuntimeConnection()
    stages = []
    queued = []
    claims = []
    monkeypatch.setattr(runtime, "prepare_production_connection", lambda *_a, **_kw: _enabled_settings())
    for stage in ("process_semantic_outbox", "process_semantic_dispatch"):
        monkeypatch.setattr(runtime, stage, lambda *_a, **kw: stages.append(kw["limit"]) or {"completed": 0, "failed": 0})
    monkeypatch.setattr(runtime, "enqueue_risk_backlog", lambda *_a, **kw: queued.append(kw["limit"]) or ())
    monkeypatch.setattr(runtime, "claim_risk_evaluation_jobs", lambda *_a, **kw: claims.append(kw["limit"]) or [{
        "job_id": "fixture-job", "lease_token": "fixture-lease", "attempt_count": 1, "max_attempts": 5,
    }])
    monkeypatch.setattr(runtime, "load_risk_evaluation_work_item", lambda *_a, **_kw: SimpleNamespace(evaluation_mode="enabled"))
    monkeypatch.setattr(runtime, "execute_risk_evaluation", lambda *_a, **_kw: SimpleNamespace(
        evaluation_mode="enabled", finding_created=False,
    ))
    cycle = runtime.run_once(limit=limit, connect_factory=lambda: conn, archive=object())
    assert queued == [expected] and claims == [1] * expected
    assert stages == [min(limit, 128)] * 2
    assert cycle["completed"] == expected and cycle["failed"] == 0
    assert conn.closed


def test_facts_cycle_persists_normalized_actions_without_dispatch_or_risk(monkeypatch) -> None:
    _configure_stages(monkeypatch, facts=True)
    from server.sli.semantic import semantic_production_runtime as runtime

    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
    monkeypatch.setenv("ADLOG_SEMANTIC_RUNTIME_MODE", "facts-v1")
    conn = _RuntimeConnection()
    calls: list[str] = []
    monkeypatch.setattr(
        runtime,
        "prepare_production_connection",
        lambda actual, **_kwargs: _facts_settings(),
    )
    monkeypatch.setattr(
        runtime,
        "process_semantic_outbox",
        lambda *_args, **_kwargs: calls.append("outbox")
        or {"completed": 1, "failed": 0, "normalized": 1, "actions": 1},
    )
    monkeypatch.setattr(
        runtime,
        "process_semantic_dispatch",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("facts mode must not dispatch")
        ),
    )
    monkeypatch.setattr(
        runtime,
        "enqueue_risk_backlog",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("facts mode must not enqueue risk")
        ),
    )

    archive = object()
    cycle = runtime.run_once(
        limit=1,
        connect_factory=lambda: conn,
        archive=archive,
    )

    assert calls == ["outbox"]
    assert cycle["runtime_mode"] == "facts-v1"
    assert cycle["risk_queued"] == 0
    assert cycle["findings_created"] == 0
    assert cycle["dispatch"] == {"completed": 0, "failed": 0, "relations": 0}
    assert conn.queries == []
    assert conn.closed is True


@pytest.mark.parametrize("limit,expected", [(1, 1), (40, 40), (10000, 128)])
def test_investigation_cycle_dispatches_relations_without_risk_or_findings(monkeypatch, limit, expected) -> None:
    from server.sli.semantic import semantic_production_runtime as runtime

    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
    monkeypatch.setenv("ADLOG_SEMANTIC_RUNTIME_MODE", "investigation-v1")
    monkeypatch.setattr(
        runtime.SemanticFeatureSettings,
        "from_env",
        classmethod(lambda cls: _investigation_settings()),
    )
    conn = _RuntimeConnection()
    calls: list[str] = []
    outbox_kwargs: list[dict[str, object]] = []
    monkeypatch.setattr(
        runtime,
        "prepare_production_connection",
        lambda *_args, **_kwargs: _investigation_settings(),
    )
    monkeypatch.setattr(
        runtime,
        "process_semantic_outbox",
        lambda *_args, **kwargs: outbox_kwargs.append(dict(kwargs))
        or calls.append("outbox")
        or {"completed": 1, "failed": 0, "normalized": 1, "actions": 1},
    )
    dispatch_kwargs: list[dict[str, object]] = []
    monkeypatch.setattr(
        runtime,
        "process_semantic_dispatch",
        lambda *_args, **kwargs: dispatch_kwargs.append(dict(kwargs))
        or calls.append("dispatch")
        or {"completed": 1, "failed": 0, "relations": 1},
    )
    monkeypatch.setattr(
        runtime,
        "enqueue_risk_backlog",
        lambda *_args, **_kwargs: pytest.fail("investigation mode must not queue risk"),
    )

    archive = object()
    cycle = runtime.run_once(
        limit=limit,
        connect_factory=lambda: conn,
        archive=archive,
    )

    assert calls == ["outbox", "dispatch"]
    assert cycle["runtime_mode"] == "investigation-v1"
    assert cycle["risk_queued"] == 0
    assert cycle["findings_created"] == 0
    assert cycle["dispatch"]["relations"] == 1
    identities = runtime.investigation_rule_identity_tuples()
    assert outbox_kwargs[0]["limit"] == expected
    assert outbox_kwargs[0]["allowed_rule_identities"] == identities
    assert dispatch_kwargs == [{
        "archive": archive,
        "settings": _investigation_settings(),
        "limit": expected,
        "allowed_rule_identities": identities,
    }]
    assert conn.queries == []
    assert conn.closed is True


def test_facts_cycle_forwards_exact_source_ids_without_dispatch_or_risk(monkeypatch) -> None:
    _configure_stages(monkeypatch, facts=True)
    from server.sli.semantic import semantic_production_runtime as runtime

    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
    monkeypatch.setenv("ADLOG_SEMANTIC_RUNTIME_MODE", "facts-v1")
    conn = _RuntimeConnection()
    seen: list[object] = []
    monkeypatch.setattr(runtime, "prepare_production_connection", lambda *_args, **_kwargs: _facts_settings())
    monkeypatch.setattr(
        runtime,
        "process_semantic_outbox",
        lambda *_args, **kwargs: seen.append(kwargs.get("source_event_ids"))
        or {"completed": 2, "failed": 0, "normalized": 2, "actions": 2},
    )
    monkeypatch.setattr(runtime, "process_semantic_dispatch", lambda *_args, **_kwargs: pytest.fail("facts must not dispatch"))
    monkeypatch.setattr(runtime, "enqueue_risk_backlog", lambda *_args, **_kwargs: pytest.fail("facts must not queue risk"))

    result = runtime.run_once(
        limit=2, connect_factory=lambda: conn, archive=object(), source_event_ids=(7, 8)
    )

    assert seen == [(7, 8)]
    assert result["findings_created"] == 0


class _AdminConnection:
    def __enter__(self) -> "_AdminConnection":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def cursor(self) -> _Cursor:
        return _Cursor({})


class _CredentialCursor:
    def __init__(self) -> None:
        self.connection = SimpleNamespace(
            info=SimpleNamespace(dbname="sli_test_semantic")
        )
        self.executed: list[str] = []

    def execute(self, query: object) -> None:
        self.executed.append(repr(query).casefold())


def test_ephemeral_semantic_login_gets_only_direct_database_connect() -> None:
    from server.sli.semantic import semantic_production_credentials as credentials

    cursor = _CredentialCursor()
    role, password = credentials.create_ephemeral_login(cursor)

    assert credentials._ROLE_PATTERN.fullmatch(role)
    assert password
    assert len(cursor.executed) == 3
    assert "create role" in cursor.executed[0]
    assert "grant adlog_semantic_worker" in cursor.executed[1]
    assert "grant connect on database" in cursor.executed[2]
    assert "sli_test_semantic" in cursor.executed[2]
    assert role in cursor.executed[2]


def test_ephemeral_semantic_login_revokes_connect_before_drop() -> None:
    from server.sli.semantic import semantic_production_credentials as credentials

    cursor = _CredentialCursor()
    role = "adlog_semantic_runtime_0123456789abcdef"

    credentials.drop_ephemeral_login(cursor, role)

    assert len(cursor.executed) == 2
    assert "revoke connect on database" in cursor.executed[0]
    assert "sli_test_semantic" in cursor.executed[0]
    assert role in cursor.executed[0]
    assert "drop role if exists" in cursor.executed[1]


def test_ephemeral_semantic_login_is_always_removed(monkeypatch) -> None:
    from server.sli.semantic import semantic_production_credentials as credentials

    events: list[tuple[str, str]] = []
    environment = {"ADLOG_SEMANTIC_WORKER_DSN": "previous"}
    monkeypatch.setattr(
        credentials,
        "connect_admin",
        lambda **_kwargs: _AdminConnection(),
    )
    monkeypatch.setattr(
        credentials,
        "create_ephemeral_login",
        lambda _cur: ("adlog_semantic_runtime_abc", "secret"),
    )
    monkeypatch.setattr(
        credentials,
        "drop_ephemeral_login",
        lambda _cur, role: events.append(("drop", role)),
    )
    monkeypatch.setattr(
        credentials,
        "worker_dsn",
        lambda **_kwargs: "runtime-dsn",
    )

    with pytest.raises(RuntimeError, match="injected"):
        with credentials.ephemeral_worker_environment(environment):
            assert environment["ADLOG_SEMANTIC_WORKER_DSN"] == "runtime-dsn"
            raise RuntimeError("injected")

    assert environment["ADLOG_SEMANTIC_WORKER_DSN"] == "previous"
    assert events == [("drop", "adlog_semantic_runtime_abc")]


def test_production_entrypoint_reports_exact_runtime_contract(monkeypatch) -> None:
    _configure_stages(monkeypatch)
    from scripts.runtime import semantic_production_worker as worker

    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
    heartbeats: list[dict[str, object]] = []

    @contextmanager
    def credentials():
        yield "adlog_semantic_runtime_abc"

    @contextmanager
    def lock():
        yield True

    monkeypatch.setattr(worker, "ephemeral_worker_environment", credentials)
    monkeypatch.setattr(worker, "_singleton_lock", lock)
    monkeypatch.setattr(worker, "_archive_reader", lambda: object())
    monkeypatch.setattr(
        worker,
        "run_production_once",
        lambda **_kwargs: {
            "status": "ok",
            "failed": 0,
            "modes": {"shadow": 0, "enabled": 0},
            "findings_created": 0,
        },
    )
    monkeypatch.setattr(
        worker,
        "record_worker_heartbeat",
        lambda **kwargs: heartbeats.append(kwargs),
    )

    exit_code = worker.run(once=True, poll_seconds=30, limit=16)

    assert exit_code == 0
    assert [item["status"] for item in heartbeats] == ["running", "idle"]
    details = heartbeats[-1]["details"]
    assert details["allowed_modes"] == ["shadow", "enabled"]
    assert details["finding_creation"] is True
    assert details["manual_runtime"] is False


def test_facts_entrypoint_heartbeat_reports_facts_mode(monkeypatch) -> None:
    _configure_stages(monkeypatch, facts=True)
    from scripts.runtime import semantic_production_worker as worker

    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
    heartbeats: list[dict[str, object]] = []

    @contextmanager
    def credentials():
        yield "adlog_semantic_runtime_abc"

    @contextmanager
    def lock():
        yield True

    monkeypatch.setenv("ADLOG_SEMANTIC_RUNTIME_MODE", "facts-v1")
    monkeypatch.setattr(worker, "ephemeral_worker_environment", credentials)
    monkeypatch.setattr(worker, "_singleton_lock", lock)
    monkeypatch.setattr(worker, "_archive_reader", lambda: object())
    monkeypatch.setattr(
        worker,
        "run_production_once",
        lambda **_kwargs: {
            "status": "ok",
            "failed": 0,
            "runtime_mode": "facts-v1",
            "modes": {"shadow": 0, "enabled": 0},
            "findings_created": 0,
        },
    )
    monkeypatch.setattr(
        worker,
        "record_worker_heartbeat",
        lambda **kwargs: heartbeats.append(kwargs),
    )

    assert worker.run(once=True, poll_seconds=30, limit=16) == 0
    details = heartbeats[-1]["details"]
    assert details["runtime_mode"] == "facts-v1"
    assert details["allowed_modes"] == []
    assert details["finding_creation"] is False


def test_investigation_entrypoint_heartbeat_reports_no_findings(monkeypatch) -> None:
    from scripts.runtime import semantic_production_worker as worker

    details = worker._details(limit=16, runtime_mode="investigation-v1")

    assert details["runtime_mode"] == "investigation-v1"
    assert details["allowed_modes"] == ["shadow"]
    assert details["finding_creation"] is False
    assert "enabled_policy" not in details
    assert details["processing_contract"]["claim_protocol_version"] == 1
    assert details["processing_contract"]["processor_version"]


def test_production_worker_keeps_singleton_lock_before_archive_or_claim(monkeypatch) -> None:
    _configure_stages(monkeypatch)
    from scripts.runtime import semantic_production_worker as worker

    @contextmanager
    def credentials():
        yield "adlog_semantic_runtime_abc"

    @contextmanager
    def lock():
        yield False

    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
    monkeypatch.setattr(worker, "ephemeral_worker_environment", credentials)
    monkeypatch.setattr(worker, "_singleton_lock", lock)
    monkeypatch.setattr(
        worker,
        "_archive_reader",
        lambda: (_ for _ in ()).throw(AssertionError("lock must precede archive access")),
    )

    assert worker.run(once=True, poll_seconds=30, limit=16) == 0


def test_supervisor_semantic_admission_updates_only_exact_flags(monkeypatch) -> None:
    from scripts.maintenance import worker_supervisor
    from server.sli.ops.worker_supervisor_secrets import WORKER_ENV_ALLOWLIST

    expected = {
        "ADLOG_SEMANTIC_PRODUCTION_ENABLED": "1",
        "ADLOG_SEMANTIC_RUNTIME_MODE": "findings-v1",
        "ADLOG_SEMANTIC_NORMALIZATION_ENABLED": "1",
        "ADLOG_SEMANTIC_ASSEMBLY_ENABLED": "1",
        "ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED": "0",
        "ADLOG_SEMANTIC_CORRELATION_ENABLED": "1",
        "ADLOG_SEMANTIC_RISK_ENGINE_ENABLED": "1",
        "ADLOG_SEMANTIC_FINDING_CREATION_ENABLED": "1",
    }
    assert set(expected) <= WORKER_ENV_ALLOWLIST
    observed: list[dict[str, str]] = []
    monkeypatch.setattr(
        worker_supervisor,
        "update_supervisor_environment",
        lambda updates: observed.append(dict(updates)) or {"status": "ok"},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "worker_supervisor.py",
            "--admit-semantic-production",
            "--confirmation",
            "ENABLE-CONTINUOUS-SEMANTIC-PRODUCTION",
        ],
    )

    assert worker_supervisor.main() == 0
    assert observed == [expected]


def test_supervisor_facts_admission_propagates_exact_mode_and_disabled_risk(monkeypatch) -> None:
    from scripts.maintenance import worker_supervisor
    from server.sli.ops.worker_supervisor_secrets import WORKER_ENV_ALLOWLIST

    expected = {
        "ADLOG_SEMANTIC_PRODUCTION_ENABLED": "1",
        "ADLOG_SEMANTIC_RUNTIME_MODE": "facts-v1",
        "ADLOG_SEMANTIC_NORMALIZATION_ENABLED": "1",
        "ADLOG_SEMANTIC_ASSEMBLY_ENABLED": "1",
        "ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED": "0",
        "ADLOG_SEMANTIC_CORRELATION_ENABLED": "0",
        "ADLOG_SEMANTIC_RISK_ENGINE_ENABLED": "0",
        "ADLOG_SEMANTIC_FINDING_CREATION_ENABLED": "0",
    }
    assert set(expected) <= WORKER_ENV_ALLOWLIST
    observed: list[dict[str, str]] = []
    monkeypatch.setattr(
        worker_supervisor,
        "update_supervisor_environment",
        lambda updates: observed.append(dict(updates)) or {"status": "ok"},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "worker_supervisor.py",
            "--admit-semantic-facts",
            "--confirmation",
            "ENABLE-CONTINUOUS-SEMANTIC-FACTS",
        ],
    )

    assert worker_supervisor.main() == 0
    assert observed == [expected]


def test_supervisor_investigation_admission_propagates_exact_mode_without_risk(monkeypatch) -> None:
    from scripts.maintenance import worker_supervisor
    from server.sli.ops.worker_supervisor_secrets import WORKER_ENV_ALLOWLIST

    expected = {
        "ADLOG_SEMANTIC_PRODUCTION_ENABLED": "1",
        "ADLOG_SEMANTIC_RUNTIME_MODE": "investigation-v1",
        "ADLOG_SEMANTIC_NORMALIZATION_ENABLED": "1",
        "ADLOG_SEMANTIC_ASSEMBLY_ENABLED": "1",
        "ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED": "0",
        "ADLOG_SEMANTIC_CORRELATION_ENABLED": "1",
        "ADLOG_SEMANTIC_RISK_ENGINE_ENABLED": "0",
        "ADLOG_SEMANTIC_FINDING_CREATION_ENABLED": "0",
    }
    assert set(expected) <= WORKER_ENV_ALLOWLIST
    observed: list[dict[str, str]] = []
    monkeypatch.setattr(
        worker_supervisor,
        "update_supervisor_environment",
        lambda updates: observed.append(dict(updates)) or {"status": "ok"},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "worker_supervisor.py",
            "--admit-semantic-investigation",
            "--confirmation",
            "ENABLE-CONTINUOUS-SEMANTIC-INVESTIGATION",
        ],
    )

    assert worker_supervisor.main() == 0
    assert observed == [expected]


def test_supervisor_admission_accepts_only_known_versioned_or_legacy_modes() -> None:
    from scripts.maintenance import worker_supervisor

    assert worker_supervisor.semantic_production_admitted(
        {
            "ADLOG_SEMANTIC_PRODUCTION_ENABLED": "1",
            "ADLOG_SEMANTIC_RUNTIME_MODE": "facts-v1",
        }
    )
    assert worker_supervisor.semantic_production_admitted(
        {
            "ADLOG_SEMANTIC_PRODUCTION_ENABLED": "1",
            "ADLOG_SEMANTIC_RUNTIME_MODE": "investigation-v1",
        }
    )
    assert worker_supervisor.semantic_production_admitted(
        {"ADLOG_SEMANTIC_PRODUCTION_ENABLED": "true"}
    )
    assert not worker_supervisor.semantic_production_admitted(
        {
            "ADLOG_SEMANTIC_PRODUCTION_ENABLED": "1",
            "ADLOG_SEMANTIC_RUNTIME_MODE": "unsupported-v1",
        }
    )


def test_supervisor_semantic_revoke_disables_the_complete_chain(monkeypatch) -> None:
    from scripts.maintenance import worker_supervisor

    expected = {
        "ADLOG_SEMANTIC_PRODUCTION_ENABLED": "0",
        "ADLOG_SEMANTIC_RUNTIME_MODE": "disabled",
        "ADLOG_SEMANTIC_NORMALIZATION_ENABLED": "0",
        "ADLOG_SEMANTIC_ASSEMBLY_ENABLED": "0",
        "ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED": "0",
        "ADLOG_SEMANTIC_CORRELATION_ENABLED": "0",
        "ADLOG_SEMANTIC_RISK_ENGINE_ENABLED": "0",
        "ADLOG_SEMANTIC_FINDING_CREATION_ENABLED": "0",
    }
    observed: list[tuple[dict[str, str], set[str]]] = []
    monkeypatch.setattr(
        worker_supervisor,
        "update_supervisor_environment_with_removals",
        lambda updates, removals: observed.append((dict(updates), set(removals))) or {"status": "ok"},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "worker_supervisor.py",
            "--revoke-semantic-production",
            "--confirmation",
            "DISABLE-CONTINUOUS-SEMANTIC-PRODUCTION",
        ],
    )

    assert worker_supervisor.main() == 0
    assert observed == [(
        expected,
        {"ADLOG_SEMANTIC_V2_QUARANTINE_REPAIR_PLAN_DIGEST"},
    )]


def test_production_worker_honors_stop_request_between_cycles(monkeypatch) -> None:
    _configure_stages(monkeypatch)
    from scripts.runtime import semantic_production_worker as worker

    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
    heartbeats: list[dict[str, object]] = []

    @contextmanager
    def credentials():
        yield "adlog_semantic_runtime_abc"

    @contextmanager
    def lock():
        yield True

    monkeypatch.setattr(worker, "ephemeral_worker_environment", credentials)
    monkeypatch.setattr(worker, "_singleton_lock", lock)
    monkeypatch.setattr(worker, "_archive_reader", lambda: object())
    monkeypatch.setattr(worker, "stop_requested", lambda _started_at: True)
    monkeypatch.setattr(
        worker,
        "run_production_once",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("stop must be checked before the next cycle")
        ),
    )
    monkeypatch.setattr(
        worker,
        "record_worker_heartbeat",
        lambda **kwargs: heartbeats.append(kwargs),
    )

    assert worker.run(once=False, poll_seconds=30, limit=16) == 0
    assert [item["status"] for item in heartbeats] == ["stopped"]
    assert heartbeats[0]["phase"] == "production_stop_requested"


@pytest.mark.parametrize("production", [False, True])
@pytest.mark.parametrize("activity", [
    {"completed": 128, "failed": 0},
    {"completed": 0, "failed": 1},
    {"completed": 0, "failed": 0, "processing": {"claimed": 1}},
    {"completed": 0, "failed": 0, "dispatch": {"claimed": 1}},
    {"completed": 0, "failed": 0, "risk_queued": 1},
])
def test_continuous_workers_drain_before_idle_sleep(monkeypatch, production, activity):
    from scripts.runtime import semantic_production_worker, semantic_worker

    _configure_stages(monkeypatch, facts=True)
    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
    monkeypatch.setenv("ADLOG_SEMANTIC_RUNTIME_MODE", "facts-v1")
    worker = semantic_production_worker if production else semantic_worker
    monkeypatch.setattr(worker, "_singleton_lock", lambda: nullcontext(True))
    monkeypatch.setattr(worker, "log_event", lambda *args, **kw: None)
    if production:
        monkeypatch.setattr(worker, "postgres_secret_parts", lambda _name: True)
        monkeypatch.setattr(worker, "_archive_reader", lambda: object())
        monkeypatch.setattr(worker, "stop_requested", lambda _started: False)
    results = [activity.copy(), activity.copy(), {"completed": 0, "failed": 0}]
    cycles = []
    heartbeats = []
    sleeps = []

    class EndLoop(BaseException):
        pass

    def cycle(**kwargs):
        if not results:
            pytest.fail("worker polled after an empty cycle without sleeping")
        cycles.append(kwargs["limit"])
        return results.pop(0)

    def sleep(seconds):
        sleeps.append(seconds)
        raise EndLoop

    monkeypatch.setattr(worker, "run_production_once" if production else "run_once", cycle)
    monkeypatch.setattr(worker, "record_worker_heartbeat", lambda **kw: heartbeats.append(kw))
    monkeypatch.setattr(worker.time, "sleep", sleep)

    with pytest.raises(EndLoop):
        worker.run(once=False, poll_seconds=30, limit=10000)

    assert cycles == [128, 128, 128]
    assert sleeps == [30]
    assert [h["phase"] for h in heartbeats[1::2]] == (
        ["production_drain", "production_drain", "production_sleep"] if production
        else ["drain", "drain", "sleep"])
    assert heartbeats[-1]["status"] == "idle"


@pytest.mark.parametrize("production", [False, True])
@pytest.mark.parametrize("once", [False, True])
def test_worker_iteration_errors_keep_backoff_and_once_exit(monkeypatch, production, once):
    from scripts.runtime import semantic_production_worker, semantic_worker

    _configure_stages(monkeypatch, facts=True)
    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
    monkeypatch.setenv("ADLOG_SEMANTIC_RUNTIME_MODE", "facts-v1")
    worker = semantic_production_worker if production else semantic_worker
    monkeypatch.setattr(worker, "_singleton_lock", lambda: nullcontext(True))
    monkeypatch.setattr(worker, "log_event", lambda *args, **kw: None)
    monkeypatch.setattr(worker, "log_internal_error", lambda *args, **kw: "fixture-error")
    monkeypatch.setattr(worker, "record_worker_heartbeat", lambda **kw: None)
    if production:
        monkeypatch.setattr(worker, "postgres_secret_parts", lambda _name: True)
        monkeypatch.setattr(worker, "_archive_reader", lambda: object())
        monkeypatch.setattr(worker, "stop_requested", lambda _started: False)

    def cycle(**kwargs):
        raise RuntimeError("fixture guard failure")

    class EndLoop(BaseException):
        pass

    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        raise EndLoop

    monkeypatch.setattr(worker, "run_production_once" if production else "run_once", cycle)
    monkeypatch.setattr(worker.time, "sleep", sleep)

    if once:
        assert worker.run(once=True, poll_seconds=30, limit=128) == 1
        assert sleeps == []
    else:
        with pytest.raises(EndLoop):
            worker.run(once=False, poll_seconds=30, limit=128)
        assert sleeps == [30]


def test_production_worker_checks_stop_between_busy_batches(monkeypatch):
    from scripts.runtime import semantic_production_worker as worker

    _configure_stages(monkeypatch, facts=True)
    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
    monkeypatch.setenv("ADLOG_SEMANTIC_RUNTIME_MODE", "facts-v1")
    monkeypatch.setattr(worker, "_singleton_lock", lambda: nullcontext(True))
    monkeypatch.setattr(worker, "postgres_secret_parts", lambda _name: True)
    monkeypatch.setattr(worker, "_archive_reader", lambda: object())
    monkeypatch.setattr(worker, "log_event", lambda *args, **kw: None)
    checks = iter([False, True])
    monkeypatch.setattr(worker, "stop_requested", lambda _started: next(checks))
    heartbeats = []
    monkeypatch.setattr(worker, "record_worker_heartbeat", lambda **kw: heartbeats.append(kw))
    monkeypatch.setattr(worker, "run_production_once", lambda **kw: {"completed": 128, "failed": 0})
    monkeypatch.setattr(worker.time, "sleep", lambda _seconds: pytest.fail("busy worker must not sleep"))

    assert worker.run(once=False, poll_seconds=30, limit=128) == 0
    assert heartbeats[-1]["phase"] == "production_stop_requested"


@pytest.mark.parametrize("production", [False, True])
@pytest.mark.parametrize("extra_args,expected", [([], 128), (["--limit", "37"], 37)])
def test_worker_cli_batch_default_and_override(monkeypatch, production, extra_args, expected):
    from scripts.runtime import semantic_production_worker, semantic_worker

    worker = semantic_production_worker if production else semantic_worker
    calls = []
    monkeypatch.setattr(sys, "argv", ["semantic-worker", "--once", *extra_args])
    monkeypatch.setattr(worker, "run", lambda **kw: calls.append(kw) or 0)

    assert worker.main() == 0
    assert calls == [{"once": True, "poll_seconds": 30, "limit": expected}]
