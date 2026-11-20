"""Synthetic isolated PostgreSQL schema; real agent lifecycle locking.

The separate 279 migration tests require the actual migrated schema. This
fixture exercises concurrent runtime code, not migration applicability.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import pytest
from tests.migrations.test_agent_snapshot_locks_postgres_integration import snapshot_database, _wait_for_lock
from tests.unit.test_agent_registry import lifecycle, request  # noqa: F401
from tests.migrations.test_agent_sequence_recovery279 import _packet
from server.sli.agent_ingest import PostgresLedger, receive_packet
from server.sli.agents import registry, sequence_recovery as recovery
from server.sli.agents.ca import AgentError

pytestmark=pytest.mark.postgres_integration


def _observe(db):
    with db['connect']() as conn,conn.cursor() as cur:
        identity=registry.authenticate(cur,db['ca'],db['der'])
        value=_packet({'id':db['agent_id'],'host_id':db['host_id']},db['key'],5)
        assert receive_packet(PostgresLedger(cur),identity=identity,public_key=db['key'].public_key(),value=value)['error_code']=='agent_sequence_gap'
        oid=recovery.list_gaps(cur,db['agent_id'],access={'platform_owner':True})['gaps'][0]['id']
    return value,oid


def test_recovery_authorization_serializes_with_revocation(snapshot_database):
    db=snapshot_database;_,oid=_observe(db)
    with db['connect']() as blocker,db['connect']() as contender:
        blocker.execute('select id from sli_agents where id=%s for update',(db['agent_id'],))
        pid=contender.info.backend_pid
        def authorize():
            with contender.cursor() as cur:
                return recovery.authorize_all(cur,{'agent_id':db['agent_id'],'observation_ids':[oid],'preview_token':recovery.recovery_preview(cur,db['agent_id'])['preview_token'],'confirm_loss':True},actor='test',access={'platform_owner':True})
        with ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(authorize)
            _wait_for_lock(db,pid)
            blocker.execute("update sli_agents set status='disabled' where id=%s",(db['agent_id'],))
            blocker.commit()
            with pytest.raises(AgentError,match='stale'):future.result(timeout=5)
        contender.rollback()


def test_authorized_ingress_waits_for_owner_transaction(snapshot_database):
    db=snapshot_database;value,oid=_observe(db)
    with db['connect']() as owner,db['connect']() as ingress:
        with owner.cursor() as cur:
            recovery.authorize_all(cur,{'agent_id':db['agent_id'],'observation_ids':[oid],'preview_token':recovery.recovery_preview(cur,db['agent_id'])['preview_token'],'confirm_loss':True},actor='test',access={'platform_owner':True})
        def deliver():
            with ingress.cursor() as cur:
                identity=registry.authenticate(cur,db['ca'],db['der'])
                result=receive_packet(PostgresLedger(cur),identity=identity,public_key=db['key'].public_key(),value=value)
            ingress.commit()
            return result
        with ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(deliver)
            _wait_for_lock(db,ingress.info.backend_pid)
            owner.commit()
            assert future.result(timeout=5)['status']=='committed'


def test_expired_permission_does_not_commit(snapshot_database,monkeypatch):
    db=snapshot_database;value,oid=_observe(db)
    with db['connect']() as conn,conn.cursor() as cur:
        recovery.authorize_all(cur,{'agent_id':db['agent_id'],'observation_ids':[oid],'preview_token':recovery.recovery_preview(cur,db['agent_id'])['preview_token'],'confirm_loss':True},actor='test',access={'platform_owner':True})
    monkeypatch.setattr(recovery,'AUTH_TTL',timedelta(seconds=-1))
    with db['connect']() as conn,conn.cursor() as cur:
        identity=registry.authenticate(cur,db['ca'],db['der'])
        assert receive_packet(PostgresLedger(cur),identity=identity,public_key=db['key'].public_key(),value=value)['error_code']=='agent_sequence_gap'
        assert PostgresLedger(cur).latest(db['agent_id'],'sli.heartbeat') is None
