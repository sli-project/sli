"""Real migrated-PostgreSQL recovery; synthetic rows are transaction-rolled back."""
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
import os
import pytest
from cryptography.hazmat.primitives.asymmetric import ec


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
