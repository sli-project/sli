"""Synthetic PostgreSQL coverage for the report predicate and unchanged ACL."""
import json
import re
from pathlib import Path

import pytest

from tests.migrations.historical_postgres import historical_connection
from tests.migrations.test_core_job_profiles_postgres_integration import (
    profile_connection,  # noqa: F401
)
from tests.migrations.test_file_audit_reports_migration191 import (
    report_database,  # noqa: F401
)

PATH = Path(__file__).resolve().parents[2] / "config/postgres_migrations/288_file_audit_service_filter.sql"


def test_migration_changes_only_report_filter_and_cursor_contract():
    sql = PATH.read_text("utf-8")
    previous = (PATH.parent / "236_file_audit_evidence.sql").read_text("utf-8")
    start = "create or replace function sli_plugin_file_audit.report_rows("
    function = sql.split(start, 1)[1].split("\nreset role;", 1)[0]
    old = previous.split(start, 1)[1].split("\nrevoke all on function sli_plugin_file_audit.report_rows", 1)[0]
    predicate = r"and \(coalesce\(p_after->'show_service' = 'true'::jsonb,false\)\s+or \(a.subject_sid='S-1-5-18' and a.operation='access_check'\) is not true\)"
    assert len(re.findall(predicate, function)) == 2
    assert function.count("'service_filter_version',1,") == 2
    assert function.count("p_after->>'at' is null or") == 2
    function = re.sub(predicate, "", function)
    function = function.replace("'service_filter_version',1,", "").replace("p_after->>'at' is null or", "p_after is null or")
    assert re.sub(r"\s+", " ", function).strip() == re.sub(r"\s+", " ", old).strip()
    assert not re.search(r"\b(grant|revoke|create role)\b", sql, re.IGNORECASE)
    assert "where version=286 and name='sigma_rule_labels'" in sql
    assert "where version=287 and name='workstation_inventory_job'" in sql
    assert sql.strip().endswith("commit;")


@pytest.fixture
def historical_325(tmp_path, monkeypatch):
    # 325 is the historical predecessor of the separate guarded NPS migration.
    # Exercise the actual successor unwind on that complete schema and ledger.
    with historical_connection(tmp_path, monkeypatch, (325, "t109_workstation_path")) as conn:
        yield conn


@pytest.mark.postgres_integration
@pytest.mark.postgres_owned_cluster
def test_disposable_fixture_unwinds_and_restores_exact_288(historical_325):
    from tests.migrations import t070_fixture

    conn = historical_325
    signature = t070_fixture.SIGNATURE

    def state():
        return conn.execute("""select pg_get_functiondef(oid), proowner, proacl
            from pg_catalog.pg_proc where oid=to_regprocedure(%s)""", (signature,)).fetchone()

    before = state()
    ledger = conn.execute("select version,name,sha256 from public.schema_migrations order by version").fetchall()
    with t070_fixture.without_successors(conn):
        _exercise_exact_288(conn, state)
    assert state() == before
    assert conn.execute("select version,name,sha256 from public.schema_migrations order by version").fetchall() == ledger


def _exercise_exact_288(conn, state):
    from tests.migrations import t070_fixture

    signature = t070_fixture.SIGNATURE
    before = state()
    with pytest.raises(ValueError, match="t070_fixture_successor_invalid"), conn.transaction():
        conn.execute("update public.schema_migrations set name='synthetic_foreign' where version=288")
        t070_fixture.preflight(conn)
    assert state() == before
    with pytest.raises(ValueError, match="t070_fixture_successor_invalid"), conn.transaction():
        conn.execute("set local role adlog_file_audit_owner")
        conn.execute(f"alter function {signature} set search_path=public,pg_temp")
        conn.execute("reset role")
        t070_fixture.preflight(conn)
    assert state() == before
    t070_fixture.remove(conn)
    assert conn.execute("select count(*) from public.schema_migrations where version=288").fetchone()[0] == 0
    assert state()[1:] == before[1:]
    conn.execute(PATH.read_text("utf-8"))
    assert state() == before


@pytest.mark.postgres_integration
@pytest.mark.parametrize("successor", [(300, "owner_recovery"), (299, "login_account_throttle"), (297, "agent_stream_import_health"), (296, "agent_runtime_switch")])
@pytest.mark.parametrize("drift", ["name", "future", "forward_hash", "rollback_hash", "missing_rollback"])
def test_disposable_fixture_rejects_unattested_successor_before_mutation(profile_connection, monkeypatch, drift, successor):  # noqa: F811
    from tests.migrations import t070_fixture

    conn = profile_connection
    version, name = successor
    with conn.transaction():
        if drift == "name":
            conn.execute("update public.schema_migrations set name='synthetic_foreign' where version=%s", (version,))
        elif drift == "future":
            conn.execute("insert into public.schema_migrations(version,name) select greatest(coalesce(max(version),0),306)+1,'synthetic_future' from public.schema_migrations")
        else:
            suffix = ".sql" if drift == "forward_hash" else ".rollback.sql"
            target = t070_fixture.ROOT / f"{version}_{name}{suffix}"
            original = Path.read_bytes

            def changed_bytes(path):
                if path == target:
                    if drift == "missing_rollback":
                        raise FileNotFoundError(path)
                    return original(path) + b"\n-- synthetic drift\n"
                return original(path)

            monkeypatch.setattr(Path, "read_bytes", changed_bytes)
        ledger = conn.execute("select version,name,sha256 from public.schema_migrations order by version").fetchall()
        before = conn.execute("select pg_get_functiondef(%s::regprocedure)", (t070_fixture.SIGNATURE,)).fetchone()
        with pytest.raises(ValueError, match="t070_fixture_successor_invalid"), t070_fixture.without_successors(conn):
            pytest.fail("unattested chain admitted")
        assert conn.execute("select version,name,sha256 from public.schema_migrations order by version").fetchall() == ledger
        assert conn.execute("select pg_get_functiondef(%s::regprocedure)", (t070_fixture.SIGNATURE,)).fetchone() == before
        assert conn.execute("select to_regclass('public.sli_agent_runtime_switches') is not null").fetchone()[0]


@pytest.mark.parametrize("failure_point", ["before_function", "after_function"])
def test_failed_update_restores_function_acl_and_ledger(report_database, failure_point):  # noqa: F811
    conn = report_database
    conn.execute("insert into public.schema_migrations values(286,'sigma_rule_labels'),(287,'workstation_inventory_job')")
    signature = "sli_plugin_file_audit.report_rows(jsonb,text,timestamptz,timestamptz,text,boolean,text,text,jsonb,integer)"

    def state():
        return conn.execute("""select pg_get_functiondef(oid) as definition, proowner, proacl
            from pg_proc where oid=to_regprocedure(%s)""", (signature,)).fetchone()

    before = state()
    source = PATH.read_text("utf-8")
    injection = "do $$ begin raise exception 'synthetic failure'; end $$;\n"
    marker = ("create or replace function sli_plugin_file_audit.report_rows(" if failure_point == "before_function"
              else "reset role;\nset local role adlog_storage_owner;")
    assert source.count(marker) == 1
    source = source.replace(marker, injection + marker)
    with pytest.raises(Exception, match="synthetic failure"):
        conn.execute(source)
    conn.execute("rollback")
    assert state() == before
    assert conn.execute("select count(*) as count from public.schema_migrations where version=288").fetchone()["count"] == 0


def test_service_filter_counts_pages_and_preserves_function_acl(report_database):  # noqa: F811
    conn = report_database
    # The existing synthetic fixture starts at 191; provide only the later
    # columns and empty delivery tables used by the current report function.
    conn.execute("alter table sli_plugin_file_audit.observations add column normalized jsonb")
    conn.execute("""create table public.sli_agent_receipts
        (agent_id uuid, module_id text, envelope jsonb, sequence bigint, packet_id uuid, received_at timestamptz);
        create table public.sli_agent_packet_inbox (packet_id uuid, imported_at timestamptz);
        alter table public.sli_agent_receipts owner to adlog_file_audit_owner;
        alter table public.sli_agent_packet_inbox owner to adlog_file_audit_owner;
        insert into public.schema_migrations values(286,'sigma_rule_labels'),(287,'workstation_inventory_job')""")
    signature = "sli_plugin_file_audit.report_rows(jsonb,text,timestamptz,timestamptz,text,boolean,text,text,jsonb,integer)"
    before = conn.execute("select proowner, proacl from pg_proc where oid=to_regprocedure(%s)", (signature,)).fetchone()
    conn.execute(PATH.read_text("utf-8"))
    assert conn.execute("select proowner, proacl from pg_proc where oid=to_regprocedure(%s)", (signature,)).fetchone() == before

    agent = "00000000-0000-4000-8000-000000000001"
    roots = [{"agent_id": agent, "source_instance_id": "source", "collection_scope_id": "scope",
              "source_name": "Synthetic", "share_name": "Share", "path": "C:\\Synthetic"}]
    cases = [("S-1-5-18", "access_check", "failure"), ("S-1-5-18", "write", "success"),
             (None, "access_check", "success"), ("S-1-5-18", "unknown", "success"),
             ("S-1-1-0", "access_check", "success")]
    for i, (sid, operation, outcome) in enumerate(cases):
        conn.execute("""insert into sli_plugin_file_audit.actions(action_id,contract_version,agent_id,source_instance_id,
            collection_scope_id,observed_at,subject_sid,path,operation,outcome,correlation_state,projection_version)
            values(%s,1,%s,'source','scope','2026-10-10T09:00Z',%s,'C:\\Synthetic\\File',%s,%s,'complete',1)""",
            (f"{i:064x}", agent, sid, operation, outcome))
    conn.execute("set role adlog_user")

    def read(tab, after=None, show=False, limit=2):
        opts = {**(after or {}), "show_service": show}
        return conn.execute("""select sli_plugin_file_audit.report_rows(%s::jsonb,%s,'2026-10-10T00:00Z',
            '2026-10-11T00:00Z',null,true,null,null,%s::jsonb,%s) as data""",
            (json.dumps(roots), tab, json.dumps(opts), limit)).fetchone()["data"]

    for show, expected in [(False, 4), (True, 5)]:
        first = read("actions", show=show)
        seen = list(first["items"])
        page = first
        while page["has_more"]:
            page = read("actions", after=page["after"], show=show)
            seen.extend(page["items"])
        assert first["filtered_count"] == expected == len(seen)
        assert len({row["id"] for row in seen}) == expected
        assert any(row["subject_sid"] is None for row in seen)
        overview = read("overview", show=show)
        assert overview["items"][0]["actions"] == expected
        assert overview["summary"]["write"] == 1
        assert overview["summary"]["denials"] == int(show)
        assert read("access-denials", show=show)["filtered_count"] == int(show)
    conn.execute("reset role")


def test_successor_fixture_restores_completed_rollbacks_when_a_later_rollback_fails(monkeypatch):
    from tests.migrations import t070_fixture

    monkeypatch.setattr(t070_fixture, "assert_disposable_database", lambda _: None)
    monkeypatch.setattr(t070_fixture, "_capture_predecessor_hash", lambda _: None)
    class Result:
        def fetchall(self):
            return [(300, "owner_recovery", None), (301, "identity_attack_rules", None),
                    (302, "attack_precursors", None), (303, "evsearch_fact_publication", None),
                    (304, "nps_agent_row_lock", None), (305, "agent_group_approval_delivery", None),
                    (306, "password_policy_reconciliation", "873bc537dbd499d5dc5c3a804183ace542e3cbbfc23b338475b5b766fbf8f02b")]
    class Connection:
        def __init__(self):
            self.calls = []
        def execute(self, sql, params=None):
            self.calls.append((sql, params))
            if sql.startswith("select version,name,sha256"):
                return Result()
            if "sli_agent_group_delivery_v305" in sql and "rollback" in sql.lower():
                raise RuntimeError("synthetic rollback failure")
        def rollback(self):
            self.calls.append(("ROLLBACK", None))
    conn = Connection()
    with pytest.raises(RuntimeError, match="synthetic rollback failure"), t070_fixture.without_successors(conn):
        pytest.fail("unexpected admission")
    assert any(sql == "ROLLBACK" for sql, _ in conn.calls)
    assert any(params == ("873bc537dbd499d5dc5c3a804183ace542e3cbbfc23b338475b5b766fbf8f02b", 306) for _, params in conn.calls)


def test_successor_fixture_aborted_body_rolls_back_before_restoration(monkeypatch):
    from tests.migrations import t070_fixture
    monkeypatch.setattr(t070_fixture, "assert_disposable_database", lambda _: None)
    calls = []
    class Result:
        def fetchall(self): return []
    class Connection:
        def execute(self, sql, params=None):
            calls.append("select")
            return Result()
        def rollback(self): calls.append("rollback")
    monkeypatch.setattr(t070_fixture, "preflight", lambda _: calls.append("preflight"))
    monkeypatch.setattr(t070_fixture, "_capture_predecessor_hash", lambda _: None)
    monkeypatch.setattr(t070_fixture, "_restore_predecessor_hash", lambda *_: calls.append("restore_hash"))
    with pytest.raises(RuntimeError, match="body failed"), t070_fixture.without_successors(Connection()):
        raise RuntimeError("body failed")
    assert calls == ["select", "preflight", "rollback", "preflight", "restore_hash"]


def test_successor_fixture_missing_predecessor_blocks_replay_and_preserves_both_errors(monkeypatch):
    from tests.migrations import t070_fixture
    monkeypatch.setattr(t070_fixture, "assert_disposable_database", lambda _: None)
    calls = []
    class Result:
        def fetchall(self): return []
    class Connection:
        def execute(self, sql, params=None):
            calls.append(sql)
            return Result()
        def rollback(self): calls.append("rollback")
    checks = []
    def missing(_):
        checks.append(True)
        if len(checks) == 2: raise ValueError("missing 288")
    monkeypatch.setattr(t070_fixture, "preflight", missing)
    monkeypatch.setattr(t070_fixture, "_capture_predecessor_hash", lambda _: None)
    with pytest.raises(ExceptionGroup, match="t070_restoration_uncertain") as caught:
        with t070_fixture.without_successors(Connection()):
            raise RuntimeError("body after remove")
    assert [str(e) for e in caught.value.exceptions] == ["body after remove", "missing 288"]
    assert len(calls) == 2


def test_predecessor_checksum_restores_saved_and_rejects_conflicts():
    from tests.migrations import t070_fixture
    class Result:
        def __init__(self, value): self.value = value
        def fetchone(self): return (self.value,)
    class Connection:
        def __init__(self, value): self.value = value
        def execute(self, sql, params=None):
            if sql.startswith("update "): self.value = params[0]
            return Result(self.value)
    conn = Connection(None)
    t070_fixture._restore_predecessor_hash(conn, "saved-pinned-hash")
    assert conn.value == "saved-pinned-hash"
    with pytest.raises(ValueError, match="t070_fixture_predecessor_hash_conflict"):
        t070_fixture._restore_predecessor_hash(Connection("foreign-hash"), "saved-pinned-hash")
    untouched = Connection(None)
    t070_fixture._restore_predecessor_hash(untouched, None)
    assert untouched.value is None


def test_successor_fixture_restores_predecessor_checksum_after_body(monkeypatch):
    from tests.migrations import t070_fixture
    monkeypatch.setattr(t070_fixture, "assert_disposable_database", lambda _: None)
    monkeypatch.setattr(t070_fixture, "preflight", lambda _: None)
    pinned = json.loads((t070_fixture.ROOT.parents[1] / "deploy/linux/native_pg_ledger.json").read_text("utf-8"))["files"]["config/postgres_migrations/288_file_audit_service_filter.sql"]
    class Result:
        def __init__(self, rows): self.rows = rows
        def fetchall(self): return self.rows
        def fetchone(self): return self.rows[0] if self.rows else None
    class Connection:
        def __init__(self): self.checksum = pinned
        def execute(self, sql, params=None):
            if sql.startswith("select version,name,sha256"): return Result([])
            if sql.startswith("select sha256"): return Result([(self.checksum,)])
            if sql.startswith("update "): self.checksum = params[0]; return Result([])
            raise AssertionError(sql)
        def rollback(self): pass
    conn = Connection()
    with t070_fixture.without_successors(conn):
        conn.checksum = None  # exact migration 288 reinserts its ledger row without sha256
    assert conn.checksum == pinned
