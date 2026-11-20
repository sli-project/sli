"""Real migrated-PostgreSQL recovery; synthetic rows are transaction-rolled back."""
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
import os
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from server.sli.agent_ingest import PostgresLedger, receive_packet
from sli_agent.envelope import make_packet
from sli_agent.modules import HeartbeatModule


def test_additive_recovery_journal_has_no_new_privileges():
    sql=(Path(__file__).resolve().parents[2]/'config/postgres_migrations/279_agent_sequence_recovery.sql').read_text()
    assert "version=278 and name='file_ransom_policy_readiness'" in sql
    assert "values(279,'agent_sequence_recovery')" in sql
    assert 'grant ' not in sql.lower() and 'delete ' not in sql.lower()
    assert sql.startswith('begin;') and sql.rstrip().endswith('commit;')


@pytest.fixture
def recovery_db():
    dsn=os.getenv('ADLOG_TEST_PG_DSN')
    if not dsn: pytest.skip('disposable migrated PostgreSQL required')
    psycopg=pytest.importorskip('psycopg')
    from psycopg.rows import dict_row
    from tests.postgres_integration_guard import assert_disposable_database
    conn=psycopg.connect(dsn,row_factory=dict_row)
    assert_disposable_database(conn)
    try:
        with conn.cursor() as cur:
            cur.execute("select name from schema_migrations where version=279")
            assert cur.fetchone()['name']=='agent_sequence_recovery'
            agent={'id':str(uuid4()),'host_id':str(uuid4()),'key_fingerprint':'a'*64,'assigned_modules':[]}
            cur.execute('insert into sli_agents(id,host_id,key_fingerprint) values(%s,%s,%s)',(agent['id'],agent['host_id'],agent['key_fingerprint']))
            yield conn,cur,agent,ec.generate_private_key(ec.SECP256R1())
    finally:
        conn.rollback();conn.close()


def _packet(agent,key,seq):
    from dataclasses import replace
    now=datetime.now(timezone.utc)
    sample=HeartbeatModule(agent['host_id']).collect(None,now=now)
    sample=replace(sample,cursor_before={'strategy':'record_id','token':str(seq-1) if seq>1 else ''},cursor_after={'strategy':'record_id','token':str(seq)})
    return make_packet(key,agent_id=agent['id'],sequence=seq,sample=sample,now=now)


@pytest.mark.postgres_integration
def test_native_recovery_authorization_loss_and_ack_are_atomic(recovery_db):
    from server.sli.agents import sequence_recovery as recovery
    conn,cur,agent,key=recovery_db
    ledger=PostgresLedger(cur)
    def receive(value): return receive_packet(ledger,identity=agent,public_key=key.public_key(),value=value)
    assert receive(_packet(agent,key,1))['status']=='committed'
    value=_packet(agent,key,5)
    assert receive(value)['error_code']=='agent_sequence_gap'
    gaps=recovery.list_gaps(cur,agent['id'],access={'platform_owner':True})['gaps']
    assert len(gaps)==1 and gaps[0]['missing_packets']=='3' and gaps[0]['loss_event_count'] is None
    oid=gaps[0]['id'];body={'observation_id':oid,'confirm_loss':True}
    assert recovery.authorize(cur,body,actor='session:1',access={'platform_owner':True})['status']=='authorized'
    cur.execute('savepoint packet_attempt')
    assert receive(value)['status']=='committed'
    assert recovery.list_gaps(cur,agent['id'],access={'platform_owner':True})['gaps'][0]['status']=='accepted'
    cur.execute('rollback to savepoint packet_attempt')
    assert ledger.latest(agent['id'],'sli.heartbeat')['sequence']==1
    assert recovery.list_gaps(cur,agent['id'],access={'platform_owner':True})['gaps'][0]['status']=='authorized'
    assert receive(value)['status']=='committed'
    assert receive(value)['status']=='duplicate'
    assert receive(_packet(agent,key,6))['status']=='committed'
    assert receive(_packet(agent,key,3))['status']=='rejected'
    cur.execute("select count(*) as n from sli_agent_audit where target=%s and action='sequence_gap_accepted'",(agent['id'],))
    assert cur.fetchone()['n']==1


@pytest.mark.postgres_integration
@pytest.mark.parametrize('change',['key','tip'])
def test_native_stale_owner_preview_cannot_authorize(recovery_db,change):
    from server.sli.agents import sequence_recovery as recovery
    from server.sli.agents.ca import AgentError
    _,cur,agent,key=recovery_db;ledger=PostgresLedger(cur)
    receive_packet(ledger,identity=agent,public_key=key.public_key(),value=_packet(agent,key,5))
    oid=recovery.list_gaps(cur,agent['id'],access={'platform_owner':True})['gaps'][0]['id']
    if change=='key': cur.execute("update sli_agents set key_fingerprint=%s where id=%s",('b'*64,agent['id']))
    else: receive_packet(ledger,identity=agent,public_key=key.public_key(),value=_packet(agent,key,1))
    with pytest.raises(AgentError,match='stale'):
        recovery.authorize(cur,{'observation_id':oid,'confirm_loss':True},actor='session:1',access={'platform_owner':True})

@pytest.mark.postgres_integration
def test_native_journal_latest_uses_numeric_order(recovery_db):
    from server.sli.agents import sequence_recovery as recovery
    from psycopg.types.json import Jsonb
    _,cur,agent,_=recovery_db
    # Explicit synthetic ids avoid modifying the identity sequence.
    # Lexical and numeric order disagree; this transaction is rolled back.
    low,high=900000000000000009,1000000000000000000
    for oid in (low,high):
        cur.execute("insert into sli_agent_audit(id,action,actor,target,details) overriding system value values(%s,%s,%s,%s,%s)",
            (oid,recovery.OBSERVED,'test',agent['id'],Jsonb({'module_id':'sli.heartbeat'})))
    assert recovery._latest(cur,agent['id'],'sli.heartbeat')['id']==str(high)


def _synthetic_second_stream(cur, agent):
    """Journal-only fixture for multi-stream transaction checks, not ingress proof."""
    from server.sli.agents.registry import audit
    from server.sli.agents import sequence_recovery as recovery
    now=datetime.now(timezone.utc)
    audit(cur,recovery.OBSERVED,'test',agent['id'],module_id='sli.synthetic-test',
          packet_id=str(uuid4()),envelope_hash='b'*64,previous_hash=None,
          key_fingerprint=agent['key_fingerprint'],expected_sequence='1',received_sequence='8',
          missing_packets='7',previous_observed_at=None,packet_observed_at=now.isoformat(),
          loss_event_count=None,loss_time_bounds_known=False,first_buffer_proven=False)


@pytest.mark.postgres_integration
def test_native_batch_rejects_new_stream_then_authorizes_exact_preview(recovery_db):
    from server.sli.agents import sequence_recovery as recovery
    from server.sli.agents.ca import AgentError
    _,cur,agent,key=recovery_db
    receive_packet(PostgresLedger(cur),identity=agent,public_key=key.public_key(),value=_packet(agent,key,5))
    old=recovery.recovery_preview(cur,agent['id'])
    _synthetic_second_stream(cur,agent)
    with pytest.raises(AgentError,match='stale'):
        recovery.authorize_all(cur,{'agent_id':agent['id'],'observation_ids':old['observation_ids'],'preview_token':old['preview_token'],'confirm_loss':True},actor='test',access={'platform_owner':True})
    cur.execute("select count(*) as n from sli_agent_audit where target=%s and action='sequence_gap_authorized'",(agent['id'],))
    assert cur.fetchone()['n']==0
    preview=recovery.recovery_preview(cur,agent['id'])
    assert len(preview['streams'])==2
    result=recovery.authorize_all(cur,{'agent_id':agent['id'],'observation_ids':preview['observation_ids'],'preview_token':preview['preview_token'],'confirm_loss':True},actor='test',access={'platform_owner':True})
    assert result['observation_ids']==preview['observation_ids']
    cur.execute("select count(*) as n from sli_agent_audit where target=%s and action='sequence_gap_authorized'",(agent['id'],))
    assert cur.fetchone()['n']==2


@pytest.mark.postgres_integration
def test_native_batch_audit_failure_rolls_back_whole_authorization(recovery_db,monkeypatch):
    from server.sli.agents import sequence_recovery as recovery
    _,cur,agent,key=recovery_db
    receive_packet(PostgresLedger(cur),identity=agent,public_key=key.public_key(),value=_packet(agent,key,5))
    _synthetic_second_stream(cur,agent)
    preview=recovery.recovery_preview(cur,agent['id'])
    ids=preview['observation_ids']
    original=recovery.authorize
    def fail_second(cursor,body,**kwargs):
        if body['observation_id']==ids[1]:raise RuntimeError('synthetic audit failure')
        return original(cursor,body,**kwargs)
    monkeypatch.setattr(recovery,'authorize',fail_second)
    cur.execute('savepoint batch_attempt')
    with pytest.raises(RuntimeError,match='synthetic'):
        recovery.authorize_all(cur,{'agent_id':agent['id'],'observation_ids':ids,'preview_token':preview['preview_token'],'confirm_loss':True},actor='test',access={'platform_owner':True})
    cur.execute('rollback to savepoint batch_attempt')
    cur.execute("select count(*) as n from sli_agent_audit where target=%s and action='sequence_gap_authorized'",(agent['id'],))
    assert cur.fetchone()['n']==0
