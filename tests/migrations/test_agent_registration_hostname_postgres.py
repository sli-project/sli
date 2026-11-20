"""Synthetic rows under actual migrated permissions; no runtime enrollment."""
import os
from uuid import uuid4

import pytest

from tests.postgres_integration_guard import assert_disposable_database

pytestmark = pytest.mark.postgres_integration


def test_initial_hostname_insert_and_read_need_no_new_update_permission():
    psycopg = pytest.importorskip('psycopg')
    dsn = os.environ.get('ADLOG_TEST_PG_DSN')
    if not dsn:
        pytest.skip('Disposable migrated PostgreSQL required')
    with psycopg.connect(dsn) as conn:
        assert_disposable_database(conn)
        conn.execute('set local role adlog_user')
        assert conn.execute("select has_column_privilege(current_user,'public.sli_agents','registration_host_name','UPDATE')").fetchone() == (False,)
        first, second = uuid4(), uuid4()
        conn.execute('''insert into public.sli_agents(id,host_id,key_fingerprint,registration_host_name)
            values(%s,%s,%s,'pc.example.invalid')''', (first,uuid4(),'a'*64))
        conn.execute('''insert into public.sli_agents(id,host_id,key_fingerprint)
            values(%s,%s,%s)''', (second,uuid4(),'b'*64))
        assert conn.execute('select registration_host_name from public.sli_agents where id=%s', (first,)).fetchone() == ('pc.example.invalid',)
        assert conn.execute('select registration_host_name from public.sli_agents where id=%s', (second,)).fetchone() == (None,)
        with pytest.raises(psycopg.errors.InsufficientPrivilege), conn.transaction():
            conn.execute("update public.sli_agents set registration_host_name='changed.example.invalid' where id=%s", (first,))
        with pytest.raises(psycopg.errors.CheckViolation), conn.transaction():
            conn.execute('''insert into public.sli_agents(id,host_id,key_fingerprint,registration_host_name)
                values(%s,%s,%s,%s)''', (uuid4(),uuid4(),'c'*64,'invalid\nhost'))
        conn.rollback()
