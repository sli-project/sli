"""R02 forward migration, scoped readback and durable suppression on disposable PG."""
from dataclasses import asdict, replace
import json
from pathlib import Path

import pytest

from server.sli.semantic import file_ransom as ransom, file_ransom_runtime as worker
from tests.migrations.test_qw_semantic_input_migration228 import pg as pg
from tests.migrations.test_qw_finding_notifications_migration229 import publication_pg as publication_pg
from tests.migrations.test_file_ransom_migration232 import (
    ransomware_pg as ransomware_pg, seed_result, publish_jobs,
)
from tests.unit.test_file_ransom import NOW
from tests.unit.test_file_ransom_details import approval

PATH = Path(__file__).resolve().parents[2] / "config/postgres_migrations/240_file_ransom_details.sql"


def test_forward_migration_uses_main_predecessor_and_does_not_activate_sources():
    sql = PATH.read_text("utf-8")
    assert list(PATH.parent.glob("240_*.sql")) == [PATH]
    assert "version=237 and name='entity_context_health'" in sql
    assert "where version>=240" in sql and "values(240,'file_ransom_details')" in sql
    assert sql.splitlines()[1] == "begin;" and sql.strip().endswith("commit;")
    assert "insert into public.finding_evidence_source_bindings" not in sql
    assert "grant select on public.semantic_file_ransom_members to adlog_user" not in sql


def roots(selected):
    return json.dumps([{"agent_id": selected.agent_id, "source_instance_id": selected.scope.source_instance_id,
                        "collection_scope_id": selected.scope.collection_scope_id}])


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_sql_details_bounds_scope_modes_and_two_channel_intents(ransomware_pg):
    import psycopg
    from psycopg.rows import dict_row

    admin, login, selected = ransomware_pg
    result, = seed_result(admin, selected)
    with psycopg.connect(login, row_factory=dict_row) as conn:
        assert worker.run_once(conn.cursor(), rule=selected, now=NOW)["jobs"] == 1
        assert publish_jobs(conn)[0].finding_created
    ids = json.dumps([result["result_id"]])
    with psycopg.connect(admin, row_factory=dict_row) as conn:
        conn.execute("set role adlog_user")
        read = "select public.read_file_ransom_details(%s::jsonb,%s::jsonb) as details"
        details = conn.execute(read, (roots(selected), ids)).fetchone()["details"][result["result_id"]]
        assert details["state"] == "admitted" and details["evaluation_mode"] == "enabled"
        assert details["first_seen"] == details["last_seen"]
        assert details["episode_key"] and not details["incomplete"]
        other = replace(selected, scope=replace(selected.scope, collection_scope_id="scope:other"))
        assert conn.execute(read, (roots(other), ids)).fetchone()["details"] == {}
        assert conn.execute(read, (roots(selected), json.dumps(["a" * 64]))).fetchone()["details"] == {}
        conn.execute("reset role")
        assert conn.execute("select count(*) as n from notification_outbox").fetchone()["n"] == 2
    with pytest.raises(psycopg.errors.InsufficientPrivilege), psycopg.connect(admin) as conn:
        conn.execute("set role adlog_user")
        conn.execute("select * from semantic_file_ransom_members")
    with pytest.raises(psycopg.Error), psycopg.connect(admin) as conn:
        conn.execute(read, (roots(selected), json.dumps(["a" * 64] * 101)))


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_sql_exclusion_is_durable_replay_safe_and_keeps_native_file_rows(ransomware_pg):
    import psycopg
    from psycopg.rows import dict_row

    admin, login, selected = ransomware_pg
    selected = replace(selected, exclusions=(approval(),))
    result, = seed_result(admin, selected)
    with psycopg.connect(login, row_factory=dict_row) as conn:
        assert worker.run_once(conn.cursor(), rule=selected, now=NOW) == {"state": "processed", "members": 1, "jobs": 0}
    with psycopg.connect(login, row_factory=dict_row) as conn:
        assert worker.run_once(conn.cursor(), rule=replace(selected, exclusions=()), now=NOW)["members"] == 0
    with psycopg.connect(admin, row_factory=dict_row) as conn:
        assert conn.execute("select count(*) as n from sli_plugin_file_audit.actions").fetchone()["n"] == 20
        for table in ("notification_outbox", "findings", "semantic_qw_signals", "semantic_file_ransom_episodes"):
            assert conn.execute("select count(*) as n from " + table).fetchone()["n"] == 0
        conn.execute("set role adlog_user")
        read = "select public.read_file_ransom_details(%s::jsonb,%s::jsonb) as details"
        item = conn.execute(read, (roots(selected), json.dumps([result["result_id"]]))).fetchone()["details"][result["result_id"]]
        assert item["state"] == "excluded" and item["episode_key"] is None
        assert item["exclusion"] == asdict(approval())


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_sql_invalid_suppression_and_revoked_source_are_not_readable(ransomware_pg):
    import psycopg
    from psycopg.rows import dict_row

    admin, login, selected = ransomware_pg
    result, = seed_result(admin, selected)
    with psycopg.connect(login, row_factory=dict_row) as conn:
        worker.run_once(conn.cursor(), rule=selected, now=NOW)
    with pytest.raises(psycopg.errors.CheckViolation), psycopg.connect(admin) as conn:
        conn.execute("insert into semantic_file_ransom_members(checkpoint_key,result_id,scope_json,exclusion_json) "
                     "values(%s,%s,%s::jsonb,%s::jsonb)", (
                         "f" * 64, "e" * 64, json.dumps(asdict(selected.scope)),
                         json.dumps(asdict(approval()) | {"active_to": "2027-01-01T00:00:00Z"})))
    with psycopg.connect(admin, row_factory=dict_row) as conn:
        conn.execute("delete from finding_evidence_source_bindings")
        conn.execute("set role adlog_user")
        assert conn.execute("select public.read_file_ransom_details(%s::jsonb,%s::jsonb) as details", (
            roots(selected), json.dumps([result["result_id"]]))).fetchone()["details"] == {}


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_sql_two_sids_two_roots_replay_and_one_intent_per_channel(ransomware_pg):
    import psycopg
    from psycopg.rows import dict_row
    from server.sli.semantic import semantic_risk_runtime_repository as runtime
    from tests.unit.test_file_audit_rules import SID

    admin, login, selected = ransomware_pg
    other = replace(selected, scope=replace(selected.scope, collection_scope_id="scope:two"))
    with psycopg.connect(admin, row_factory=dict_row) as conn:
        conn.execute("insert into finding_evidence_source_bindings select principal_oid,principal_name,"
                     "installation_id,plugin_id,source_instance_id,source_generation,'scope:two',"
                     "storage_kind,log_source_id,agent_key,agent_id from finding_evidence_source_bindings")
        runtime.register_risk_policy(conn.cursor(), policy=ransom.risk_policy(other, policy_id="fixture-other"))
        conn.execute("update semantic_risk_policies set lifecycle_status='enabled'")
        conn.execute("insert into semantic_policy_admission values('fixture-other',1,true)")
    for root_index, candidate in enumerate((selected, other)):
        for sid_index, sid in enumerate((SID, "S-1-5-21-1-2-3-9999")):
            seed_result(admin, candidate, offset=(root_index * 2 + sid_index) * 100, subject_sid=sid)
        with psycopg.connect(login, row_factory=dict_row) as conn:
            assert worker.run_once(conn.cursor(), rule=candidate, now=NOW)["jobs"] == 2
            assert len(publish_jobs(conn)) == 2
        with psycopg.connect(login, row_factory=dict_row) as conn:
            assert worker.run_once(conn.cursor(), rule=candidate, now=NOW)["jobs"] == 0
    with psycopg.connect(admin) as conn:
        for table in ("semantic_file_ransom_episodes", "findings", "semantic_finding_publications"):
            assert conn.execute("select count(*) from " + table).fetchone()[0] == 4
        assert conn.execute("select channel,count(*) from notification_outbox group by channel order by channel").fetchall() == [
            ("smtp", 4), ("telegram", 4)]
