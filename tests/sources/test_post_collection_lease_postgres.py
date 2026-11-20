"""Real SQL fencing/recovery regressions on the isolated CI PostgreSQL clone."""
import os

import pytest

from server.sli.core import postgres_runtime_pipeline as runtime
from server.sli.sources import post_collection_pipeline as pipeline
from tests.postgres_integration_guard import assert_disposable_database

pytestmark = pytest.mark.postgres_integration


@pytest.fixture
def pg(monkeypatch):
    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN is required for isolated PostgreSQL tests")
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    def connect():
        return psycopg.connect(dsn, row_factory=dict_row)

    with connect() as conn:
        assert_disposable_database(conn)
    monkeypatch.setattr(runtime, "connect", connect)
    monkeypatch.setattr(pipeline, "_require_postgres", lambda: None)
    monkeypatch.setattr(pipeline, "ensure_post_collection_schema", dict)
    return connect


def queue():
    pipeline.queue_post_collection_job(durable_job_id="lease-test", source_job_id=1, servers=[])


def expire(pg):
    with pg() as conn:
        conn.execute(
            "update post_collection_jobs set worker_lease_until=now()-interval '1 second' "
            "where durable_job_id='lease-test'"
        )


def mutations(owner):
    return [
        lambda: pipeline.heartbeat_post_collection_job("lease-test", **owner),
        lambda: pipeline.update_post_collection_findings("lease-test", status="completed", **owner),
        lambda: pipeline.update_post_collection_job("lease-test", status="completed", **owner),
        lambda: pipeline.update_post_collection_job("lease-test", status="failed", **owner),
    ]


@pytest.mark.parametrize("next_worker", ["worker-b", "worker-a"])
def test_stale_attempt_cannot_mutate_new_claim_even_when_worker_name_reused(pg, next_worker):
    queue()
    a = pipeline.claim_post_collection_job("lease-test", worker_id="worker-a")
    expire(pg)
    assert pipeline.recover_stale_post_collection_jobs()["requeued"] == 1
    b = pipeline.claim_post_collection_job("lease-test", worker_id=next_worker)
    assert b["attempt_count"] == a["attempt_count"] + 1
    before = pipeline.get_post_collection_job("lease-test")
    for mutate in mutations({"worker_id": "worker-a", "claim_attempt": a["attempt_count"]}):
        with pytest.raises(pipeline.PostCollectionLeaseLost):
            mutate()
        assert pipeline.get_post_collection_job("lease-test") == before
    owner = {"worker_id": next_worker, "claim_attempt": b["attempt_count"]}
    pipeline.heartbeat_post_collection_job("lease-test", **owner)
    pipeline.update_post_collection_findings("lease-test", status="completed", **owner)
    pipeline.update_post_collection_job("lease-test", status="completed", **owner)
    assert pipeline.get_post_collection_job("lease-test")["status"] == "completed"
    for mutate in mutations(owner):
        with pytest.raises(pipeline.PostCollectionLeaseLost):
            mutate()


def test_expired_owner_cannot_resurrect_lease_before_recovery(pg):
    queue()
    claim = pipeline.claim_post_collection_job("lease-test", worker_id="worker-a")
    expire(pg)
    before = pipeline.get_post_collection_job("lease-test")
    for mutate in mutations({"worker_id": "worker-a", "claim_attempt": claim["attempt_count"]}):
        with pytest.raises(pipeline.PostCollectionLeaseLost):
            mutate()
    assert pipeline.get_post_collection_job("lease-test") == before


def test_recovery_preserves_live_final_attempt_then_exhausts_after_expiry(pg):
    queue()
    with pg() as conn:
        conn.execute("update post_collection_jobs set max_attempts=1 where durable_job_id='lease-test'")
    claim = pipeline.claim_post_collection_job("lease-test", worker_id="worker-a")
    assert claim["attempt_count"] == claim["max_attempts"] == 1
    assert pipeline.recover_stale_post_collection_jobs() == {"requeued": 0, "exhausted": 0}
    assert pipeline.get_post_collection_job("lease-test")["status"] == "running"
    expire(pg)
    assert pipeline.recover_stale_post_collection_jobs() == {"requeued": 0, "exhausted": 1}
    assert pipeline.get_post_collection_job("lease-test")["status"] == "failed"


@pytest.mark.parametrize("status", ["queued", "running"])
def test_recovery_exhausts_unleased_final_attempt(pg, status):
    queue()
    with pg() as conn:
        conn.execute(
            "update post_collection_jobs set status=%s, attempt_count=max_attempts, "
            "worker_lease_until=null where durable_job_id='lease-test'", (status,),
        )
    assert pipeline.recover_stale_post_collection_jobs() == {"requeued": 0, "exhausted": 1}


@pytest.mark.parametrize("loss", ["owner", "generation", "expired", "terminal"])
def test_publication_guard_rejects_lost_claim(pg, loss):
    queue()
    claim = pipeline.claim_post_collection_job("lease-test", worker_id="worker-a")
    owner = {"worker_id": "worker-a", "claim_attempt": claim["attempt_count"]}
    if loss == "owner":
        owner["worker_id"] = "worker-b"
    elif loss == "generation":
        owner["claim_attempt"] += 1
    elif loss == "expired":
        expire(pg)
    else:
        pipeline.update_post_collection_job("lease-test", status="completed", **owner)
    with pytest.raises(pipeline.PostCollectionLeaseLost), pipeline.post_collection_lease_guard("lease-test", **owner):
        pytest.fail("lost attempt entered the publication critical section")


def test_publication_guard_holds_row_lock_until_promotion_finishes(pg):
    from psycopg.errors import LockNotAvailable

    queue()
    claim = pipeline.claim_post_collection_job("lease-test", worker_id="worker-a")
    with pipeline.post_collection_lease_guard(
        "lease-test", worker_id="worker-a", claim_attempt=claim["attempt_count"],
    ):
        with pytest.raises(LockNotAvailable), pg() as other:
            other.execute("set local lock_timeout='50ms'")
            other.execute(
                "update post_collection_jobs set worker_id='worker-b' where durable_job_id='lease-test'"
            )
    # The same ownership-changing mutation can proceed once publication releases the lock.
    with pg() as other:
        other.execute("set local lock_timeout='1s'")
        other.execute("update post_collection_jobs set worker_id='worker-b' where durable_job_id='lease-test'")
