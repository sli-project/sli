import json
import os
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from server.sli.storage import permanent_history_lifecycle as lifecycle


@pytest.fixture
def history(monkeypatch):
    monkeypatch.setattr(lifecycle.ad_history, "run_cycle", lambda **kw: {"status": "ok"})
    monkeypatch.setattr(lifecycle.history, "primary_read_enabled", lambda: True)
    monkeypatch.setattr(lifecycle.history, "configured_read_port", lambda: 57847)
    monkeypatch.setattr(lifecycle, "session_advisory_lock", lambda *a: nullcontext(True))
    monkeypatch.setattr(lifecycle.history, "next_after_id", lambda port: 100)
    monkeypatch.setattr(lifecycle.history, "copy_one_batch", lambda *a, **kw: {
        "status": "complete", "event_count": 0, "link_count": 0,
    })
    return lifecycle.history


def test_empty_tail_completes_without_docker_or_archive(history, monkeypatch):
    monkeypatch.setattr(history, "_container_port", lambda *a: pytest.fail("Docker invoked"))
    result = lifecycle.run_cycle(max_batches=2, apply_retention=False)
    assert result["status"] == "ok"
    assert result["history_rows_copied"] == 0
    assert result["copy_only_no_delete"] is True
    assert result["archive_lane"]["status"] == "disabled"


@pytest.mark.postgres_integration
@pytest.mark.postgres_historical(371, "password_domain_auto")
def test_compose_copy_cycle_uses_provisioned_storage_login_without_admin(tmp_path, monkeypatch):
    """Catch an undeclared admin credential in either the lock or source reads."""
    import psycopg
    import yaml
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    from deploy.linux import sli_secrets
    from tests.postgres_integration_guard import assert_disposable_database

    dsn = os.environ.get('ADLOG_TEST_PG_DSN')
    if not dsn:
        pytest.skip('isolated PostgreSQL DSN required')
    root = Path(__file__).resolve().parents[2]
    compose = yaml.safe_load((root / 'deploy/linux/docker-compose.yml').read_text('utf-8'))
    sli_secrets.validate_compose(compose)
    service = compose['services']['storage-lifecycle']
    manifest = sli_secrets.load_manifest()
    for name, value in service['environment'].items():
        if isinstance(value, str):
            if value.startswith('/run/secrets/'):
                secret = value.removeprefix('/run/secrets/')
                assert secret in service['secrets'] and secret in manifest
                path = tmp_path / secret
                path.write_text('synthetic-storage-secret', encoding='utf-8')
                value = str(path)
            monkeypatch.setenv(name, value)
    for name in ('ADLOG_PG_ADMIN_USER', 'ADLOG_PG_ADMIN_PASSWORD', 'ADLOG_PG_ADMIN_PASSWORD_FILE'):
        monkeypatch.delenv(name, raising=False)
    login = 'sli_test_lifecycle_' + uuid4().hex
    monkeypatch.setenv('ADLOG_PG_DSN', dsn)
    monkeypatch.setenv('ADLOG_STORAGE_V2_WORKER_DSN', make_conninfo(dsn, user=login))
    assert lifecycle.history._history_auth()[1] == 'synthetic-storage-secret'
    with psycopg.connect(dsn, autocommit=True) as admin:
        assert_disposable_database(admin)
        admin.execute(sql.SQL('create role {} login noinherit password {}').format(
            sql.Identifier(login), sql.Literal('synthetic-storage-secret')))
        try:
            admin.execute(sql.SQL('grant adlog_storage_worker to {} with inherit false').format(
                sql.Identifier(login)))
            monkeypatch.setattr(lifecycle.ad_history, 'run_cycle', lambda **kw: {'status': 'ok'})
            monkeypatch.setattr(lifecycle.history, 'next_after_id', lambda port: 0)

            # The real copier reads the empty PostgreSQL tail and needs no ClickHouse IO.
            result = lifecycle.run_cycle(max_batches=1)
            assert result['status'] == 'ok'
            assert result['copy_only_no_delete'] is True
            with lifecycle.history._connect() as conn:
                assert conn.execute('select current_user').fetchone()['current_user'] == 'adlog_storage_worker'
                assert conn.execute('show default_transaction_read_only').fetchone()[
                    'default_transaction_read_only'] == 'on'
                assert conn.execute('show statement_timeout').fetchone()['statement_timeout'] == '3min'
                assert conn.execute('show lock_timeout').fetchone()['lock_timeout'] == '3s'
                with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
                    conn.execute('delete from events_v2_core')
        finally:
            admin.execute(sql.SQL('drop role {}').format(sql.Identifier(login)))


def test_ad_history_publication_and_retention_are_in_the_storage_cycle(history, monkeypatch):
    seen = []
    monkeypatch.setattr(lifecycle.ad_history, "run_cycle", lambda **kw: seen.append(kw) or {
        "status": "ok", "records_published": 2, "deleted_records": 3})
    monkeypatch.setattr(lifecycle, "_retain", lambda **kw: {"status": "complete", "deleted_count": 0})
    result = lifecycle.run_cycle(max_batches=2, apply_retention=True,
                                 now=datetime(2026, 10, 7, tzinfo=timezone.utc))
    assert seen[0]["apply_retention"] is True
    assert seen[0]["max_manifests"] == 2
    assert result["ad_snapshot_history"]["deleted_records"] == 3


def test_ad_history_backlog_remains_partial_even_when_event_history_is_complete(history, monkeypatch):
    monkeypatch.setattr(lifecycle.ad_history, "run_cycle", lambda **kw: {"status": "partial"})
    assert lifecycle.run_cycle()["reason"] == "ad_snapshot_history_backlog_remaining"


@pytest.mark.parametrize("error,reason", [
    (RuntimeError("snapshot_history_source_family_missing"), "snapshot_history_source_family_missing"),
    (OSError("synthetic private connection details"), "purge_verification_or_io_failed"),
])
def test_unavailable_ad_history_blocks_all_downstream_deletion(history, monkeypatch, error, reason):
    def unavailable(**kw):
        raise error
    monkeypatch.setattr(lifecycle.ad_history, "run_cycle", unavailable)
    monkeypatch.setattr(history, "next_after_id", lambda *a: pytest.fail("copy after AD history failure"))
    monkeypatch.setattr(lifecycle.file_retention, "run_batch", lambda **kw: pytest.fail("file deletion"))
    monkeypatch.setattr(lifecycle, "_retain", lambda **kw: pytest.fail("hot deletion"))
    result = lifecycle.run_cycle(apply_retention=True)
    assert result["status"] == "blocked"
    assert result["reason"] == reason
    assert result["deleted_rows"] == 0
    assert result["copy_only_no_delete"] is True
    assert result["delete_execution_admitted"] is False
    assert "private" not in json.dumps(result)


def test_blocked_ad_history_result_cannot_be_overwritten_by_successful_event_copy(history, monkeypatch):
    monkeypatch.setattr(lifecycle.ad_history, "run_cycle", lambda **kw: {
        "status": "blocked", "reason": "snapshot_history_source_family_missing"})
    monkeypatch.setattr(lifecycle, "_retain", lambda **kw: pytest.fail("hot deletion"))
    result = lifecycle.run_cycle(apply_retention=True)
    assert result["status"] == "blocked"
    assert result["deleted_rows"] == 0


def test_batch_budget_defers_retention_and_resumes_from_published_frontier(history, monkeypatch):
    seen = []

    def copy(port, *, after_id, **kw):
        seen.append(after_id)
        return {"status": "published", "last_event_db_id": after_id + 10,
                "event_count": 10, "link_count": 20}

    monkeypatch.setattr(history, "copy_one_batch", copy)
    monkeypatch.setattr(lifecycle, "_retain", lambda **kw: pytest.fail("premature delete"))
    result = lifecycle.run_cycle(max_batches=2, apply_retention=True)
    assert seen == [100, 110]
    assert result["status"] == "partial"
    assert result["history_rows_copied"] == 20
    assert result["deleted_rows"] == 0


def test_failed_copy_never_runs_retention(history, monkeypatch):
    def fail(*a, **kw):
        raise RuntimeError("clickhouse_fact_history_readback_incomplete")
    monkeypatch.setattr(history, "copy_one_batch", fail)
    monkeypatch.setattr(lifecycle, "_retain", lambda **kw: pytest.fail("delete after failed copy"))
    result = lifecycle.run_cycle(max_batches=2, apply_retention=True)
    assert result["status"] == "blocked"
    assert result["reason"] == "clickhouse_fact_history_readback_incomplete"
    assert result["deleted_rows"] == 0
    assert result["copy_only_no_delete"] is True


def test_file_retention_runs_after_publication_and_hold_stops_hot_deletion(history, monkeypatch):
    monkeypatch.setattr(lifecycle.file_retention, "cleanup_enabled", lambda: True)
    called = []
    monkeypatch.setattr(lifecycle.file_retention, "run_batch", lambda **kw: called.append(kw) or {
        "status": "blocked", "reason": "file_audit_evidence_held"})
    monkeypatch.setattr(lifecycle, "_retain", lambda **kw: pytest.fail("delete after file hold"))
    result = lifecycle.run_cycle(apply_retention=True, now=datetime(2026, 10, 10, tzinfo=timezone.utc))
    assert len(called) == 1 and result["status"] == "blocked"
    assert result["reason"] == "file_audit_evidence_held"


def test_file_retention_never_runs_when_copy_is_unverified(history, monkeypatch):
    monkeypatch.setattr(lifecycle.file_retention, "cleanup_enabled", lambda: True)
    monkeypatch.setattr(history, "copy_one_batch", lambda *a, **kw: {
        "status": "partial", "event_count": 0, "link_count": 0})
    monkeypatch.setattr(lifecycle.file_retention, "run_batch", lambda **kw: pytest.fail("unverified cleanup"))
    result = lifecycle.run_cycle(apply_retention=True)
    assert result["status"] == "blocked"
    assert result["reason"] == "history_publication_not_verified"


def test_copy_lock_contention_is_retryable(history, monkeypatch):
    monkeypatch.setattr(lifecycle, "session_advisory_lock", lambda *a: nullcontext(False))
    result = lifecycle.run_cycle(max_batches=2, apply_retention=True)
    assert result["status"] == "partial"
    assert result["reason"] == "fact_history_copy_lock_held"


def test_retention_preserves_blocked_result_and_seven_day_cutoff(history, monkeypatch):
    def retain(**kw):
        assert kw["cutoff"] == datetime(2026, 9, 20, tzinfo=timezone.utc)
        return {"status": "blocked", "reason": "semantic_pending", "deleted_count": 0}
    monkeypatch.setattr(lifecycle, "_retain", retain)
    result = lifecycle.run_cycle(
        max_batches=2, apply_retention=True,
        now=datetime(2026, 9, 27, tzinfo=timezone.utc),
    )
    assert result["status"] == "blocked"
    assert result["reason"] == "semantic_pending"
    assert result["deleted_rows"] == 0


def test_retention_failure_stops_cycle_with_safe_reason(history, monkeypatch):
    calls = []

    def retain(**kw):
        calls.append(kw)
        raise RuntimeError("history_retention_delete_mismatch")

    monkeypatch.setattr(lifecycle, "_retain", retain)
    result = lifecycle.run_cycle(max_batches=5, apply_retention=True)
    assert len(calls) == 1
    assert result["status"] == "blocked"
    assert result["reason"] == "history_retention_delete_mismatch"
    assert result["deleted_rows"] == 0


def test_retention_progress_advances_only_after_success_and_keeps_frontier_on_failure(tmp_path, monkeypatch):
    progress = tmp_path / "runtime" / "storage-history-retention-progress.json"
    monkeypatch.setattr(lifecycle, "PROGRESS", progress)
    monkeypatch.setattr(lifecycle, "_connect_write", lambda: nullcontext(object()))
    seen = []

    def retain(connection, **kw):
        seen.append(kw["after_id"])
        return {"status": "partial", "last_scanned_id": 41, "held_count": 1}

    monkeypatch.setattr(lifecycle, "retain_batch", retain)
    lifecycle._retain(port=8123, cutoff=datetime(2026, 9, 20, tzinfo=timezone.utc), batch_size=10)
    assert json.loads(progress.read_text())["last_scanned_id"] == 41
    before = progress.read_bytes()

    def fail(connection, **kw):
        seen.append(kw["after_id"])
        raise RuntimeError("history_retention_source_changed")

    monkeypatch.setattr(lifecycle, "retain_batch", fail)
    with pytest.raises(RuntimeError, match="source_changed"):
        lifecycle._retain(port=8123, cutoff=datetime(2026, 9, 20, tzinfo=timezone.utc), batch_size=10)
    assert seen == [0, 41]
    assert progress.read_bytes() == before


@pytest.mark.parametrize("boundary", ["configuration", "copy_lock"])
def test_outer_dependencies_fail_closed_without_private_exception_text(history, monkeypatch, boundary):
    def fail(*args, **kwargs):
        raise RuntimeError("private connection string and source")

    if boundary == "configuration":
        monkeypatch.setattr(history, "primary_read_enabled", fail)
    else:
        monkeypatch.setattr(lifecycle, "session_advisory_lock", fail)
    monkeypatch.setattr(lifecycle, "_retain", lambda **kw: pytest.fail("delete after dependency failure"))
    result = lifecycle.run_cycle(apply_retention=True)
    assert result["status"] == "blocked"
    assert result["reason"] == "purge_verification_or_io_failed"
    assert result["blocked_phase"] == boundary
    assert result["deleted_rows"] == 0
    assert result["copy_only_no_delete"] is True
    assert "private" not in json.dumps(result)


def test_dependency_error_after_committed_work_keeps_the_real_deletion_count(history, monkeypatch):
    from contextlib import contextmanager

    @contextmanager
    def lock(*args):
        yield True
        raise OSError("private connection close error")

    monkeypatch.setattr(lifecycle, "session_advisory_lock", lock)
    monkeypatch.setattr(lifecycle, "_retain", lambda **kw: {"status": "complete", "deleted_count": 3})
    result = lifecycle.run_cycle(apply_retention=True)
    assert result["status"] == "blocked"
    assert result["deleted_rows"] == 3
    assert result["reason"] == "purge_verification_or_io_failed"
