"""T026 additive source metadata; disposable PostgreSQL only.

The existing267 reduced-fixture limits apply; this is not a full bootstrap test.
"""
import json
from pathlib import Path
from uuid import uuid4

import pytest

from tests.migrations.test_qw_finding_notifications_migration229 import publication_pg as publication_pg

from tests.migrations.test_file_audit_discovery_join_migration267 import (
    AGENT,
    MODULE,
    OTHER_AGENT,
    apply_if_present,
    authority_state,
    enumerate_sources,
    function_state,
    observe,
    receipt,
)
from tests.migrations.test_file_audit_discovery_join_migration267 import (
    defaults_pg as defaults_pg,  # noqa: PLC0414 -- imported pytest fixture
)
from tests.migrations.test_file_audit_discovery_join_migration267 import (
    join_pg as join_pg,  # noqa: PLC0414 -- imported pytest fixture
)
from tests.migrations.test_file_audit_discovery_join_migration267 import (
    lookup_pg as lookup_pg,  # noqa: PLC0414 -- imported pytest fixture
)
from tests.migrations.test_file_audit_discovery_join_migration267 import (
    pg as pg,  # noqa: PLC0414 -- imported pytest fixture
)

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / 'config/postgres_migrations/278_file_ransom_policy_readiness.sql'
pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]


@pytest.mark.parametrize('change', ['none', 'missing', 'agent', 'source', 'revision', 'files', 'seconds',
                                          'bad_text', 'oversized', 'object', 'array', 'boolean', 'bad_seconds'])
def test_exact_policy_readiness_keeps_source_and_authority(join_pg, request, change):
    import psycopg
    worker_dsn = request.getfixturevalue('postgres_semantic_worker_dsn')
    with psycopg.connect(join_pg, autocommit=True) as admin:
        config = {'policy_revision': '2', 'mass_operation_files': 25,
                  'mass_operation_seconds': 60, 'roots': [{'collection_scope_id': 'selected-root'}]}
        admin.execute("insert into sli_agents values(%s,'active',%s::jsonb)",
                      (AGENT, json.dumps([{'module_id': MODULE, 'enabled': True, 'config': config}])))
        observe(admin, 1)
        receipt(admin, 1)
        apply_if_present(admin)
        # A healthy non-file source must remain discoverable alongside malformed
        # retained file policy. Use real imported/committed core witness gates.
        packet = str(uuid4())
        core_module = 'sli.windows.ad-dc'
        envelope = json.dumps({'source_instance_id': 'healthy-core', 'generation': 'g1'})
        admin.execute("insert into sli_agents values(%s,'active',%s::jsonb)",
                      (OTHER_AGENT, json.dumps([{'module_id': core_module, 'enabled': True}])))
        admin.execute("insert into sli_agent_module_bindings values(%s,%s,'healthy-core')", (OTHER_AGENT, core_module))
        admin.execute("""insert into sli_agent_receipts
            (agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
            values(%s,%s,1,%s,repeat('a',64),%s::jsonb,'{"status":"committed"}')""",
            (OTHER_AGENT, core_module, packet, envelope))
        admin.execute("""insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
            values(%s,%s::jsonb,'{"contract":"sli.collection-packet.v1","header":{"channel":"Security"}}','[]',now())""",
            (packet, envelope))
        admin.execute("insert into raw_log_files values(1,%s)", ('agent-packet:' + packet,))
        admin.execute("insert into events_v2_core(id,log_source_id,raw_log_file_id) values(1,3,1)")
        # Reproduce the existing183 table and232 owner's SELECT, not new authority.
        if not admin.execute("select to_regclass('sli_plugin_file_audit.policy_revisions')").fetchone()[0]:
            ddl = (ROOT / 'config/postgres_migrations/183_file_audit_contracts.sql').read_text()
            ddl = ddl[ddl.index('create table sli_plugin_file_audit.policy_revisions'):].split('\n);', 1)[0] + '\n);'
            admin.execute(ddl)
            admin.execute('grant select on sli_plugin_file_audit.policy_revisions to adlog_storage_owner')
        retained = dict(config)
        if change == 'files':
            retained['mass_operation_files'] = 26
        if change == 'seconds':
            retained['mass_operation_seconds'] = 61
        malformed = {'bad_text': 'not-a-number', 'oversized': '9' * 1000,
                     'object': {'unexpected': 1}, 'array': [25], 'boolean': True}
        if change in malformed:
            retained['mass_operation_files'] = malformed[change]
        if change == 'bad_seconds':
            retained['mass_operation_seconds'] = '9' * 1000
        if change != 'missing':
            admin.execute('''insert into sli_plugin_file_audit.policy_revisions
                values(%s,%s,%s,now(),'session',1,%s::jsonb,repeat('a',64))''',
                (OTHER_AGENT if change == 'agent' else AGENT,
                 'foreign-source' if change == 'source' else 'selected-source',
                 3 if change == 'revision' else 2, json.dumps(retained)))
        before_function, before_authority = function_state(admin), authority_state(admin)
        # Apply actual merged277, not a forged ledger marker. The reduced fixture
        # only supplies the unrelated domains table if its earlier chain omitted it.
        if admin.execute("select to_regclass('public.domains')").fetchone()[0] is None:
            admin.execute('create table public.domains(id bigint primary key)')
        admin.execute((ROOT / 'config/postgres_migrations/277_domain_archive_selection.sql').read_text())
        admin.execute(PATH.read_text())
        assert function_state(admin)[:5] == before_function[:5]
        assert authority_state(admin) == before_authority
        # Resolve the relation as fixture admin: worker intentionally lacks schema
        # USAGE, so has_table_privilege(text) would fail before checking its ACL.
        policy_oid = admin.execute(
            "select 'sli_plugin_file_audit.policy_revisions'::regclass::oid"
        ).fetchone()[0]
        with psycopg.connect(worker_dsn, autocommit=True) as worker:
            worker.execute('set role adlog_semantic_worker')
            rows = enumerate_sources(worker)
            assert len(rows) == 2
            assert any(row['scope']['plugin_id'] == core_module for row in rows)
            file_row, = [row for row in rows if row['scope']['plugin_id'] == MODULE]
            assert file_row['config'] == config
            assert file_row['ransom_policy']['state'] == ('ready' if change == 'none' else 'waiting')
            assert not worker.execute(
                "select has_table_privilege(session_user,%s::oid,'SELECT')", (policy_oid,)
            ).fetchone()[0]
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                worker.execute('select * from sli_plugin_file_audit.policy_revisions limit 0')


def test_full_migration_rejects_missing277_before_replacing_function(join_pg):
    import psycopg
    with psycopg.connect(join_pg, autocommit=True) as admin:
        apply_if_present(admin)
        before = function_state(admin)
        assert not admin.execute('select 1 from schema_migrations where version=277').fetchone()
        with pytest.raises(psycopg.errors.RaiseException, match='migration 278 prerequisites failed'):
            admin.execute(PATH.read_text())
        admin.execute('rollback')
        assert function_state(admin) == before
        assert not admin.execute('select 1 from schema_migrations where version=278').fetchone()
