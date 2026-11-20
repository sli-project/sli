"""WR14 real queue and publication with migrated publisher rights, no extra GRANT."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from server.sli.core.job_queue import digest
from server.sli.plugins.workstations import process_paths, projection
from server.sli.plugins.workstations.jobs import _Rows
from tests.migrations.test_core_job_profiles_postgres_integration import profile_connection as profile_connection
from tests.unit.test_workstation_password_failures import native, STATION

pytestmark = pytest.mark.postgres_integration


def test_native_process_queue_is_atomic_replay_safe_and_publisher_scoped(profile_connection):
    from psycopg.types.json import Jsonb
    from psycopg.errors import RaiseException

    conn = profile_connection
    manifest = json.loads((Path(__file__).resolve().parents[2] /
                           'config/plugin_packages/sli.workstations.projection-jobs-v3.json').read_text())
    handler = manifest['handlers'][0]
    spec = {'plugin_id': 'sli.workstations', 'plugin_version': '1.0.0',
            'handler_id': handler['handler_id'], 'handler_version': handler['handler_version'],
            'job_type': 'reconcile', 'resource_profile': 'light', 'rights_profile': handler['rights_profile'],
            'input_contract': handler['input_contract'], 'result_contract': handler['result_contract'],
            'source_instance_id': 'workstations:projection', 'partition_key': handler['handler_id'],
            'manifest_sha256': digest(manifest), 'access_scope': {'mode': 'restricted', 'clauses': [{
                'source_instance_ids': ['workstations:projection'], 'collection_scope_ids': [],
                'device_ids': [], 'entity_ids': []}],
                'decision_id': 'core-workstation-projection-v1', 'policy_revision': '1'}}
    job_id, token = uuid4(), uuid4()
    row = native(number=4688, at=datetime.now(timezone.utc) - timedelta(days=30), NewProcessName=r'C:\Users\Public\fixture.exe', NewProcessId='0x11')
    rules = (projection.Projector(process_paths.PROJECTOR, process_paths.RULE_VERSION, process_paths.apply),)
    with conn.transaction():
        # Only synthetic fixtures in the disposable CI clone. No ACL changes.
        conn.execute("""insert into public.plugin_installations_v1
            (plugin_id,manifest_id,manifest_sha256,package_version,package_lifecycle,desired_activation,
             observed_health,component_runtime,queue_state,revision,immutable_evidence_count)
            values('sli.workstations','fixture',%s,'1.0.0','registered','enabled_manual',
                   'unknown','running','drained',1,1)
            on conflict(plugin_id) do update set package_version='1.0.0',package_lifecycle='registered',
                desired_activation='enabled_manual',component_runtime='running'""", (digest(manifest),))
        assert conn.execute('select public.core_workstation_projection_binding_v1(%s)', (Jsonb(spec),)).fetchone()[0]
        conn.execute("""insert into sli_jobs.jobs
            (job_id,spec,idempotency_key,plugin_id,source_instance_id,partition_key,resource_profile,
             rights_profile,state,priority,max_attempts,available_at,deadline_at,lease_token,lease_generation,lease_until)
            values(%s,%s,%s,'sli.workstations','workstations:projection','workstations.overview-project',
                   'light','workstations-projection','leased',1,3,clock_timestamp(),
                   clock_timestamp()+interval '5 minutes',%s,1,clock_timestamp()+interval '5 minutes')""",
                     (job_id, Jsonb(spec), digest(str(job_id)), token))
        conn.execute("insert into sli_plugin_workstations.station_inventory(station_id,agent_key) values(%s,%s)",
                     (STATION, row['agent_key']))
        conn.execute("""insert into sli_plugin_workstations.observations
            (id,agent_key,entity_id,family,event_id,observed_at,observation,observation_sha256,source_xml)
            values(%s,%s,1,'processes',4688,%s,%s,%s,'<Event/>')""",
                     (row['id'], row['agent_key'], row['observed_at'], Jsonb(row['observation']), digest(row['observation'])))
        work_id = conn.execute("select work_id from sli_plugin_workstations.projection_work where kind='observations' and source_id=%s",
                               (row['id'],)).fetchone()[0]
        conn.execute('set local session authorization sli_job_publisher_light')
        try:
            assert not conn.execute("select has_table_privilege(current_user,'public.sli_agents','SELECT')").fetchone()[0]
            with pytest.raises(RaiseException, match='workstation_projection_write_denied'), conn.transaction():
                projection.prepare_consumers(_Rows(conn), evaluators=rules)
            conn.execute("select set_config('sli.job_id',%s,true),set_config('sli.job_token',%s,true),"
                         "set_config('sli.job_generation','1',true)", (str(job_id), str(token)))
            projection.prepare_consumers(_Rows(conn), evaluators=rules)
            # Failure after actual INSERT must roll back both the finding and receipt.
            with pytest.raises(RuntimeError, match='fixture rollback'), conn.transaction():
                projection.run_batch(_Rows(conn), evaluators=rules, work_ids=[work_id])
                raise RuntimeError('fixture rollback')
            assert conn.execute("select count(*) from sli_plugin_workstations.check_findings where check_id='C04'").fetchone()[0] == 0
            assert conn.execute("select applied_at from sli_plugin_workstations.projection_receipts where work_id=%s and projector_key=%s",
                                (work_id, process_paths.PROJECTOR)).fetchone()[0] is None
            assert projection.run_batch(_Rows(conn), evaluators=rules, work_ids=[work_id])['processed'] == 1
            saved = conn.execute("""select fact_at,first_detected_at,revision,subject_ref,evidence_refs
                from sli_plugin_workstations.check_findings where check_id='C04'""").fetchone()
            assert saved[0] == row['observed_at'] < saved[1]
            assert saved[2] == 1 and saved[3]['signature_status'] == 'not_received'
            assert saved[3]['current_state'] == 'unknown'
            assert saved[4][0]['observation_id'] == row['id']
            assert projection.run_batch(_Rows(conn), evaluators=rules, work_ids=[work_id])['processed'] == 0
            # Direct consumer replay still cannot rewrite detection time/revision.
            process_paths.apply(_Rows(conn), STATION, {'kind': 'observations', 'payload': row})
            assert conn.execute("""select fact_at,first_detected_at,revision,subject_ref,evidence_refs
                from sli_plugin_workstations.check_findings where check_id='C04'""").fetchone() == saved
        finally:
            conn.execute('reset session authorization')
