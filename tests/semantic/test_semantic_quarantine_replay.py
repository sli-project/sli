import copy
import json
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

import pytest

from server.sli.semantic import semantic_quarantine_replay as replay


NOW = datetime(2026, 10, 9, tzinfo=timezone.utc)


def job(code="KeyError", detail=None):
    return {
        "job_id": "00000000-0000-0000-0000-000000000007",
        "source_event_id": 7, "job_kind": "normalize_event", "status": "quarantined",
        "semantic_contract_version": replay.SEMANTIC_CONTRACT_VERSION,
        "processor_id": replay.PROCESSOR_ID, "processor_version": "previous",
        "attempt_count": 5, "max_attempts": 5, "updated_at": NOW,
        "last_error_code": code,
        "last_error_detail": detail or "'published archive block not found for event 7'",
        "payload_json": {},
        "source_identity_json": {
            "id": 7, "server_id": 1, "domain_id": 2, "log_source_id": 3,
            "event_id": 4625, "time_created_utc": NOW.isoformat(),
            "normalized_hash": "a" * 64, "migrated_at": NOW.isoformat(),
            "channel": "Security", "computer": "fixture-host",
        },
    }


class Connection:
    def __init__(self, rows):
        self.rows = rows
        self.audit = []
        self.effects = []
        self.sql = []
        self.readonly = False
        self.closed = False

    @contextmanager
    def transaction(self):
        saved = copy.deepcopy((self.audit, self.effects))
        try:
            yield
        except BaseException:
            self.audit, self.effects = saved
            raise
        finally:
            self.readonly = False

    def cursor(self):
        return Cursor(self)

    def close(self):
        self.closed = True


class Cursor:
    def __init__(self, conn):
        self.conn = conn
        self.results = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=()):
        self.conn.sql.append((sql, params))
        if "set transaction read only" in sql.lower():
            self.conn.readonly = True
        if "insert into semantic_control_audit" in sql:
            assert not self.conn.readonly
            self.conn.audit.append(json.loads(params[-1]))
        elif "from semantic_processing_outbox" in sql:
            self.results = copy.deepcopy(self.conn.rows)
            if "where job_id=" in sql:
                self.results = [r for r in self.results if str(r["job_id"]) == params[0]]
        elif "from semantic_control_audit" in sql:
            self.results = [{"target": a["job_id"], "details": a} for a in self.conn.audit
                            if a["job_id"] in params[1]
                            and (a["outcome"] == "closed" or
                                 (a["outcome"] == "replayed" and a["processor_version"] == params[2]
                                  and a["assembler_version"] == params[3]))]
        else:
            self.results = []

    def fetchall(self):
        return self.results

    def fetchone(self):
        return self.results[0] if self.results else None


def selection(**kwargs):
    return replay.Selection(reasons=("KeyError", "UniqueViolation"), **kwargs)


def install_processor(monkeypatch, *, fail=False):
    def process(cur, row, *, archive, dispatch):
        assert archive is not None
        cur.conn.effects.append(row["source_event_id"])
        if fail:
            raise RuntimeError("fixture-sensitive-error-detail")
        return 1

    monkeypatch.setattr(replay, "_replay", process)


def test_dry_run_counts_without_writes_or_source_hydration(monkeypatch):
    conn = Connection([job(), job("UniqueViolation", 'duplicate key violates "canonical_actions_pkey"'),
                       job("KeyError", "unrelated lookup")])
    monkeypatch.setattr(replay, "_replay", lambda *_a, **_kw: pytest.fail("dry-run hydrated source"))
    result = replay.run(conn, selection(), archive=None)
    assert result["selected"] == 3
    assert result["retryable"] == 2
    assert result["blocked"] == 1
    assert result["decisions"] == {"fixed_source_lookup": 1, "fixed_canonical_identity": 1, "unsupported_failure": 1}
    assert len(result["plan_digest"]) == 64
    assert conn.audit == conn.effects == []
    assert "fixture-host" not in json.dumps(result)
    assert not any("for update" in sql for sql, _ in conn.sql)


def test_apply_records_success_atomically_and_repeated_apply_is_noop(monkeypatch):
    conn = Connection([job()])
    original = copy.deepcopy(conn.rows)
    install_processor(monkeypatch)
    digest = replay.run(conn, selection())["plan_digest"]
    result = replay.run(conn, selection(), archive=object(), apply=True, plan_digest=digest)
    assert result["replayed"] == 1
    assert conn.effects == [7]
    assert conn.audit[0]["reason"] == "fixed_source_lookup"
    assert conn.rows == original
    again = replay.run(conn, selection(), archive=object(), apply=True, plan_digest=digest)
    assert again["already_resolved"] == 1
    assert conn.effects == [7]
    assert len(conn.audit) == 1


@pytest.mark.parametrize("detail", [
    "canceling statement due to statement timeout",
    "cancelling statement due to statement timeout\n",
])
def test_timeout_replay_is_explicit_audited_and_idempotent(monkeypatch, detail):
    conn = Connection([job("QueryCanceled", detail)])
    original = copy.deepcopy(conn.rows)
    selected = replay.Selection(reasons=("QueryCanceled",))
    install_processor(monkeypatch)
    preview = replay.run(conn, selected)
    assert preview["decisions"] == {"retry_statement_timeout": 1}
    assert conn.effects == conn.audit == []
    result = replay.run(conn, selected, archive=object(), apply=True, plan_digest=preview["plan_digest"])
    assert result["replayed"] == 1
    assert conn.audit[0]["reason"] == "retry_statement_timeout"
    assert conn.rows == original
    again = replay.run(conn, selected, archive=object(), apply=True, plan_digest=preview["plan_digest"])
    assert again["already_resolved"] == 1 and conn.effects == [7]


@pytest.mark.parametrize("code,detail", [
    ("QueryCanceled", "canceling statement due to user request"),
    ("QueryCanceled", "canceling statement due to statement timeout\nCONTEXT: unverified"),
    ("RuntimeError", "canceling statement due to statement timeout"),
])
def test_other_cancellations_remain_blocked(code, detail):
    result = replay.run(Connection([job(code, detail)]), replay.Selection(reasons=(code,)))
    assert result["blocked"] == 1 and result["retryable"] == 0


def test_failed_replay_rolls_back_effects_and_records_safe_failure_then_can_retry(monkeypatch):
    conn = Connection([job()])
    install_processor(monkeypatch, fail=True)
    digest = replay.run(conn, selection())["plan_digest"]
    result = replay.run(conn, selection(), archive=object(), apply=True, plan_digest=digest)
    assert result["failed"] == 1
    assert conn.effects == []
    assert conn.audit[0]["outcome"] == "failed"
    assert "fixture-sensitive-error-detail" not in json.dumps(conn.audit + [result])
    install_processor(monkeypatch)
    assert replay.run(conn, selection(), archive=object(), apply=True, plan_digest=digest)["replayed"] == 1


def test_close_requires_explicit_reason_and_keeps_quarantine(monkeypatch):
    conn = Connection([job("KeyError", "unrelated lookup")])
    monkeypatch.setattr(replay, "_replay", lambda *_a, **_kw: pytest.fail("closed source hydrated"))
    closed = selection(close_reason="source_unavailable")
    digest = replay.run(conn, closed)["plan_digest"]
    result = replay.run(conn, closed, apply=True, plan_digest=digest)
    assert result["closed"] == 1
    assert conn.audit[0]["reason"] == "source_unavailable"
    assert conn.rows[0]["status"] == "quarantined"


@pytest.mark.parametrize("field,value", [
    ("last_error_detail", "changed"), ("processor_version", "changed"),
    ("updated_at", NOW.replace(day=10)), ("payload_json", {"changed": True}),
])
def test_stale_plan_refuses_writes(field, value):
    conn = Connection([job()])
    digest = replay.run(conn, selection())["plan_digest"]
    conn.rows[0][field] = value
    with pytest.raises(ValueError, match="plan_changed"):
        replay.run(conn, selection(), apply=True, plan_digest=digest)
    assert conn.audit == conn.effects == []


@pytest.mark.parametrize("kwargs", [
    {"source_id_min": 9, "source_id_max": 7}, {"source_id_min": 0},
    {"since": datetime(2026, 10, 9)}, {"since": NOW, "until": NOW},
    {"limit": 0}, {"limit": 1001}, {"close_reason": "arbitrary text"},
])
def test_invalid_selection(kwargs):
    with pytest.raises(ValueError):
        selection(**kwargs)


def test_selection_uses_bound_parameters_and_refuses_truncation():
    conn = Connection([job(), job()])
    with pytest.raises(ValueError, match="selection_limit_exceeded"):
        replay.run(conn, selection(source_id_min=7, source_id_max=9, since=NOW, until=NOW.replace(day=10), limit=1))
    sql, params = next((s, p) for s, p in conn.sql if "from semantic_processing_outbox" in s)
    assert "source_event_id >= %s" in sql and "source_event_id <= %s" in sql
    assert "updated_at >= %s" in sql and "updated_at < %s" in sql
    assert params[-1] == 2


@pytest.mark.parametrize("mutate", [
    lambda r: r.update(job_kind="semantic_replay"),
    lambda r: r.update(semantic_contract_version=999),
    lambda r: r.update(last_error_code="UniqueViolation", last_error_detail='duplicate key "other_pkey"'),
    lambda r: r["source_identity_json"].update(id=8),
    lambda r: r["source_identity_json"].update(normalized_hash="invalid"),
])
def test_unsupported_or_invalid_candidates_are_not_retried(mutate, monkeypatch):
    row = job()
    mutate(row)
    conn = Connection([row])
    monkeypatch.setattr(replay, "_replay", lambda *_a, **_kw: pytest.fail("blocked source hydrated"))
    digest = replay.run(conn, selection())["plan_digest"]
    result = replay.run(conn, selection(), apply=True, plan_digest=digest)
    assert result["blocked"] == 1
    assert not conn.audit


def test_replay_runs_real_canonical_writer_without_duplicate_on_version_bump(monkeypatch):
    from server.sli.semantic.semantic_processing import ASSEMBLER_ID, CanonicalAction

    action = CanonicalAction(action_kind="audit.policy.changed", status="observed",
                             occurred_at_utc=NOW, contribution_key="ab" * 32,
                             source_event_ids=(), attributes={"material_identity": {"source_host": "fixture-host"}})
    stable_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"adlog:canonical:{action.canonical_deduplication_key}"))

    class CanonicalCursor:
        def __init__(self):
            self.sql = ""
            self.statements = []
            self.action = {
                "canonical_action_id": stable_id, "action_kind": action.action_kind,
                "action_status": action.status, "semantic_contract_version": replay.SEMANTIC_CONTRACT_VERSION,
                "assembler_id": ASSEMBLER_ID, "assembler_version": "previous",
                "canonical_deduplication_key": bytes.fromhex(action.canonical_deduplication_key),
                "action_sha256": b"x" * 32, "attributes_json": dict(action.attributes),
            }

        def execute(self, sql, params=()):
            self.sql = sql
            self.statements.append(sql)
            assert "insert into canonical_actions" not in sql
            if "set attributes_json=" in sql:
                self.action.update(attributes_json=json.loads(params[0]), action_sha256=params[1], assembler_version=params[2])

        def fetchone(self):
            return self.action if "from canonical_actions" in self.sql else None

        def fetchall(self):
            return []

    def load(_cur, **kwargs):
        assert kwargs["source_identity"] == job()["source_identity_json"]
        assert kwargs["source_event_id"] == 7
        return {"fixture": True}

    monkeypatch.setattr(replay, "load_semantic_source_event", load)
    monkeypatch.setattr(replay, "normalize_semantic_source_payload", lambda _s: object())
    monkeypatch.setattr(replay, "load_identity_role_overrides", lambda _c, **_kw: {})
    monkeypatch.setattr(replay, "apply_identity_role_overrides", lambda n, _o: n)
    monkeypatch.setattr(replay, "persist_normalized_event", lambda _c, **_kw: "normalized-id")
    monkeypatch.setattr(replay, "assemble_canonical_actions", lambda _n: (action,))
    cur = CanonicalCursor()
    assert replay._replay(cur, job(), archive=object(), dispatch=False) == 1
    assert replay._replay(cur, job(), archive=object(), dispatch=False) == 1
    assert cur.action["canonical_action_id"] == stable_id
    assert len(cur.action["attributes_json"]["prior_interpretations"]) == 1
    assert any("pg_advisory_xact_lock" in sql for sql in cur.statements)


def test_audit_failure_rolls_back_successful_processing(monkeypatch):
    conn = Connection([job()])
    install_processor(monkeypatch)
    record = replay._record

    def fail_success(cur, row, **kwargs):
        if kwargs["outcome"] == "replayed":
            raise RuntimeError("audit unavailable")
        record(cur, row, **kwargs)

    monkeypatch.setattr(replay, "_record", fail_success)
    digest = replay.run(conn, selection())["plan_digest"]
    assert replay.run(conn, selection(), archive=object(), apply=True, plan_digest=digest)["failed"] == 1
    assert not conn.effects
    assert conn.audit[0]["outcome"] == "failed"


def test_late_job_change_is_skipped_under_source_lock(monkeypatch):
    conn = Connection([job()])
    install_processor(monkeypatch)
    digest = replay.run(conn, selection())["plan_digest"]

    def lock(_cur, **_kwargs):
        conn.rows[0]["status"] = "completed"

    monkeypatch.setattr(replay, "lock_semantic_source", lock)
    result = replay.run(conn, selection(), archive=object(), apply=True, plan_digest=digest)
    assert result["changed"] == 1
    assert conn.audit == conn.effects == []


def test_concurrent_resolution_is_rechecked_under_source_lock(monkeypatch):
    conn = Connection([job()])
    install_processor(monkeypatch)
    digest = replay.run(conn, selection())["plan_digest"]

    def lock(cur, **_kwargs):
        replay._record(cur, conn.rows[0], outcome="replayed", reason="fixed_source_lookup",
                       plan_digest=digest, dispatch=False)

    monkeypatch.setattr(replay, "lock_semantic_source", lock)
    result = replay.run(conn, selection(), archive=object(), apply=True, plan_digest=digest)
    assert result["already_resolved"] == 1
    assert not conn.effects
    assert len(conn.audit) == 1


def test_dispatch_receipt_does_not_hide_normalization_only_replay(monkeypatch):
    conn = Connection([job()])
    install_processor(monkeypatch)
    for dispatch in (False, True, True):
        scope = selection(dispatch=dispatch)
        digest = replay.run(conn, scope)["plan_digest"]
        replay.run(conn, scope, archive=object(), apply=True, plan_digest=digest)
    assert len(conn.audit) == 2
    assert conn.audit[-1]["dispatch"] is True


def test_receipt_for_changed_quarantine_does_not_hide_new_failure(monkeypatch):
    conn = Connection([job()])
    install_processor(monkeypatch)
    digest = replay.run(conn, selection())["plan_digest"]
    replay.run(conn, selection(), archive=object(), apply=True, plan_digest=digest)
    conn.rows[0]["updated_at"] = NOW.replace(day=10)
    assert replay.run(conn, selection())["retryable"] == 1


def test_apply_requires_digest_before_connecting(monkeypatch):
    monkeypatch.setattr(replay, "_connect", lambda: pytest.fail("connected without digest"))
    with pytest.raises(SystemExit) as error:
        replay.main(["--apply", "--reason", "KeyError"])
    assert error.value.code == 2


def test_cli_connection_failure_never_discloses_secret(monkeypatch, capsys):
    def connect():
        raise RuntimeError("fixture-private-connection-detail")

    monkeypatch.setattr(replay, "_connect", connect)
    assert replay.main(["--dry-run", "--reason", "KeyError"]) == 1
    assert "fixture-private-connection-detail" not in capsys.readouterr().out


@pytest.mark.parametrize("error,reason", [
    (KeyError("fixture-missing-source"), "source_unavailable"),
    (RuntimeError("canonical action identity replay conflict"), "canonical_conflict"),
    (RuntimeError("fixture-private-detail"), "replay_failed"),
])
def test_failure_classification_contains_no_exception_text(error, reason):
    assert replay._failure_reason(error) == reason


def test_source_integrity_failure_remains_quarantined(monkeypatch):
    from server.sli.storage.storage_v2_archive import ArchiveIntegrityError

    conn = Connection([job()])

    def process(*_args, **_kwargs):
        raise ArchiveIntegrityError("fixture-private-integrity-detail")

    monkeypatch.setattr(replay, "_replay", process)
    digest = replay.run(conn, selection())["plan_digest"]
    result = replay.run(conn, selection(), archive=object(), apply=True, plan_digest=digest)
    assert result["failures"] == {"source_integrity_failed": 1}
    assert conn.rows[0]["status"] == "quarantined"
    assert "fixture-private-integrity-detail" not in json.dumps(conn.audit + [result])


def test_connection_uses_explicit_replay_credentials_and_bounded_transactions(monkeypatch):
    import psycopg
    from server.sli.core import secret_files

    captured = {}

    def parts(name):
        assert name == "ADLOG_SEMANTIC_REPLAY_DSN"
        return {"host": "fixture-db", "options": "fixture-options", "application_name": "fixture-app"}

    def connect(**kwargs):
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(secret_files, "postgres_secret_parts", parts)
    monkeypatch.setattr(psycopg, "connect", connect)
    replay._connect()
    assert captured["autocommit"] is True
    assert captured["options"] == "-c statement_timeout=30000 -c lock_timeout=5000"
    assert captured["application_name"] == "sli_semantic_quarantine_replay"
