"""B1 native authority and transport budgets on synthetic disposable PostgreSQL."""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
from uuid import uuid4

import pytest

from server.sli.semantic import password_attack_v2 as detector
from server.sli.storage.evidence_ref import EvidenceScope
from tests.migrations.test_file_acl_semantic_migration265 import native_pg as native_pg
from tests.migrations.test_file_audit_acl_bridge_migration264 import acl_pg as acl_pg
from tests.migrations.test_file_audit_source_lookup_index_migration266 import observation_ddl

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/273_password_attacks_v2.sql"
SCOPE = EvidenceScope("00000000-0000-4000-8000-000000000099", "sli.windows.ad-dc", "fixture-password", "generation-1")
AGENT = "00000000-0000-4000-8000-000000000098"
MIB = 1024 * 1024
pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]


def _function(migration, name):
    source = (PATH.parent / migration).read_text("utf-8-sig")
    return "create or replace function public." + name + "(" + source.split(
        "function public." + name + "(", 1)[1].split("$$;", 1)[0] + "$$;"


@pytest.fixture
def password_base_pg(native_pg):
    """Reuse actual264/265/266; current named190/219 authority, no fake verifier."""
    import psycopg

    with psycopg.connect(native_pg, autocommit=True) as conn:
        #Actual183/186 observation DDL and the merged266 index migration after
        #the actual264/265 fixture chain;266 body/index remain exercised.
        conn.execute("set role adlog_file_audit_owner")
        observation_ddl(conn)
        conn.execute("reset role")
        conn.execute((PATH.parent / "266_file_audit_source_lookup_index.sql").read_text("utf-8-sig"))
        # Unrelated269/270/271/272 synthetic predecessor markers; not full267-272 bootstrap.
        conn.execute("insert into schema_migrations values(269,'file_audit_canonical_aggregation')")
        conn.execute("insert into schema_migrations values(270,'account_decoy_source_prefilter')")
        conn.execute("insert into schema_migrations values(271,'account_watch_source_prefilter')")
        conn.execute("insert into schema_migrations values(272,'file_audit_assignment_policy')")
        conn.execute("set role adlog_storage_owner")
        conn.execute("""
            create table public.events_v2_core(id bigint primary key,event_id integer,log_source_id bigint,
                normalized_hash bytea,raw_log_file_id bigint,time_created_utc timestamptz,event_record_id bigint);
            create table public.raw_log_files(id bigint primary key,file_path text);
            create table public.sli_agent_packet_inbox(packet_id uuid primary key,envelope jsonb,packet jsonb,
                event_rows jsonb,imported_at timestamptz);
            create table public.sli_agent_receipts(packet_id uuid primary key,module_id text,envelope jsonb,receipt jsonb);
        """)
        #203 is the actual current definition of the190-named function.
        conn.execute(_function("203_agent_semantic_timestamp_precision.sql", "read_agent_semantic_source_v190"))
        conn.execute("""revoke all on function public.read_agent_semantic_source_v190(bigint) from public;
            grant execute on function public.read_agent_semantic_source_v190(bigint) to adlog_semantic_worker;
            reset role;
            alter table public.raw_log_files owner to adlog_user;
            grant select(id,file_path) on public.raw_log_files to adlog_storage_owner;
        """)
        #264's real resolver keeps219's exact core_event branch and ACL support.
        actual = conn.execute("select pg_get_functiondef('public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text)'::regprocedure)").fetchone()[0]
        assert "encode(e.normalized_hash,'hex')=p_sha256" in actual
        assert "receipt.receipt->>'status'='committed'" in actual
        assert "file_audit_snapshot_provenance_v264" in actual
        # Coverage uses actual pre-existing157/156/domain metadata, not a new issuer.
        # Restore EMPTY prerequisites omitted by reduced unrelated264/265 fixtures.
        schema = (PATH.parents[1] / "postgres_schema.sql").read_text("utf-8-sig")
        conn.execute(schema[schema.index("create table if not exists forests"):schema.index("create table if not exists sites")])
        conn.execute("alter table public.domains owner to adlog_user")  # actual baseline.sql owner
        conn.execute("grant references on public.domains to adlog_storage_owner")  # actual153
        conn.execute("grant select(id,fqdn,netbios_name) on public.domains to adlog_storage_owner")  # actual244
        conn.execute("set role adlog_storage_owner")
        packets = (PATH.parent / "157_agent_packets.sql").read_text("utf-8-sig")
        conn.execute(packets[packets.index("create table sli_agent_module_bindings"):packets.index("create table sli_agent_receipts")])
        ad_binding = (PATH.parent / "161_ad_dc_agent.sql").read_text("utf-8-sig")
        conn.execute(ad_binding[ad_binding.index("alter table sli_agent_module_bindings"):ad_binding.index("insert into")])
        agent = (PATH.parent / "156_agent_registry.sql").read_text("utf-8-sig")
        conn.execute(agent[agent.index("create table sli_agent_audit"):agent.index("create index sli_agent_audit_revocations")])
        conn.execute("alter table public.sli_agents add column policy_revision bigint not null default 1 check(policy_revision between 1 and 9007199254740991)")
        conn.execute("revoke all on public.sli_agent_module_bindings from public,adlog_user; grant select on public.sli_agent_module_bindings to adlog_user")
        conn.execute("grant select,insert on public.sli_agent_audit to adlog_user; grant usage,select on sequence public.sli_agent_audit_id_seq to adlog_user")
        conn.execute("reset role")
    return native_pg


@pytest.fixture
def password_pg(password_base_pg):
    """Absence of273 reaches behavioral assertions, never import-time failure."""
    import psycopg
    from psycopg import sql

    login = "sli_test_password_v2_" + uuid4().hex
    with psycopg.connect(password_base_pg, autocommit=True) as conn:
        if PATH.exists():
            conn.execute(PATH.read_text("utf-8-sig"))
        conn.execute(sql.SQL("create role {} login").format(sql.Identifier(login)))
        conn.execute(sql.SQL("grant adlog_semantic_worker to {}").format(sql.Identifier(login)))
        conn.execute("""insert into public.finding_evidence_source_bindings
            select oid,rolname,%s,%s,%s,%s,'','core_event',7,null,%s
            from pg_roles where rolname=%s""",
            (SCOPE.installation_id, SCOPE.plugin_id, SCOPE.source_instance_id,
             SCOPE.source_generation, AGENT, login))
    try:
        yield password_base_pg, login
    finally:
        with psycopg.connect(password_base_pg, autocommit=True) as conn:
            conn.execute(sql.SQL("drop role {}").format(sql.Identifier(login)))


@contextmanager
def _connection(source, *, worker=False):
    import psycopg
    from psycopg import sql
    from psycopg.rows import dict_row

    dsn, login = source
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as conn:
        if worker:
            #Test superuser changes session identity to a real LOGIN role.
            #SET ROLE alone must never authorize a source.
            conn.execute(sql.SQL("set session authorization {}").format(sql.Identifier(login)))
            conn.execute("set role adlog_semantic_worker")
        yield conn


def _xml(at, native_id=1, *, size=None, unicode=False):
    prefix = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
              '<System><EventID>4625</EventID>'
              f'<EventRecordID>{native_id}</EventRecordID><TimeCreated SystemTime="{at.isoformat()}"/>'
              '<Computer>fixture-collector</Computer></System><EventData>'
              '<Data Name="TargetUserName">fixture-account</Data><Data Name="TargetDomainName">fixture</Data>'
              '<Data Name="Status">0xc000006a</Data><Data Name="IpAddress">203.0.113.1</Data>'
              '<Data Name="Padding">')
    suffix = '</Data></EventData></Event>'
    if size is None:
        return prefix + suffix
    remaining = size - len((prefix + suffix).encode("utf-8"))
    assert remaining >= 0
    padding = "я" * (remaining // 2) + "x" * (remaining % 2) if unicode else "x" * remaining
    result = prefix + padding + suffix
    assert len(result.encode("utf-8")) == size
    return result


def _seed(conn, count=1, *, at=None, start=1):
    at = at or conn.execute("select statement_timestamp()-interval '300 seconds' as at").fetchone()["at"]
    envelope = {"agent_id": AGENT, "source_instance_id": SCOPE.source_instance_id,
                "generation": SCOPE.source_generation}
    #One packet/event: tests do not hide unbounded native190 JSON traversal.
    conn.execute("""insert into events_v2_core
        select g,4625,7,decode(lpad(to_hex(g),64,'0'),'hex'),g,%s,g from generate_series(%s::bigint,%s::bigint) g""",
        (at, start, start + count - 1))
    conn.execute("""insert into raw_log_files
        select id,'agent-packet:'||md5('password-v2-fixture-'||id::text)::uuid::text from events_v2_core
        where id between %s and %s""", (start, start + count - 1))
    conn.execute("""insert into sli_agent_packet_inbox
        select md5('password-v2-fixture-'||id::text)::uuid,%s::jsonb,
            '{"header":{"source":"fixture-collector","channel":"Security"}}'::jsonb,
            jsonb_build_array(jsonb_build_object('record_id',id::text,'event_id','4625',
                'time_created',time_created_utc::text,'computer_name','fixture-collector','channel','Security',
                'xml',replace(%s,'<EventRecordID>1</EventRecordID>',
                    '<EventRecordID>'||id::text||'</EventRecordID>'))),statement_timestamp()
        from events_v2_core where id between %s and %s""", (json.dumps(envelope), _xml(at), start, start + count - 1))
    conn.execute("""insert into sli_agent_receipts
        select i.packet_id,'sli.windows.ad-dc',i.envelope,'{"status":"committed"}'::jsonb
        from sli_agent_packet_inbox i where not exists(select 1 from sli_agent_receipts r where r.packet_id=i.packet_id)""")
    return at


def _replace_xml(conn, native_id, xml):
    conn.execute("""update sli_agent_packet_inbox set event_rows=jsonb_set(event_rows,'{0,xml}',to_jsonb(%s::text))
        where packet_id=md5('password-v2-fixture-'||%s::text)::uuid""", (xml, native_id))


def _window(conn, scope=None):
    return conn.execute("select * from public.read_default_password_window_v2(%s::jsonb)",
                        (json.dumps(asdict(SCOPE) if scope is None else scope),)).fetchall()


def _batch(rows):
    assert rows and rows[0]["record_kind"] == "metadata"
    assert sum(row["record_kind"] == "metadata" for row in rows) == 1
    metadata = rows[0]["metadata"]
    assert metadata["version"] == "sli.password.v2.window.1"
    assert all(rows[0][field] is None for field in
               ("source_event_id", "event_id", "occurred_at_utc", "sha256", "source_xml"))
    assert all(row["record_kind"] == "event" and row["metadata"] is None for row in rows[1:])
    return metadata, rows[1:]


def _occurrence(row):
    return {"ref": {"storage_kind": "core_event", "native_id": str(row["source_event_id"]),
                    "sha256": row["sha256"], "scope": asdict(SCOPE)},
            "at": row["occurred_at_utc"].isoformat(), "xml_bytes": len(row["source_xml"].encode("utf-8")),
            "xml_sha256": sha256(row["source_xml"].encode("utf-8")).hexdigest()}


def _retained(conn, occurrences, scope=None):
    return conn.execute("select * from public.read_password_retained_proof_v2(%s::jsonb,%s::jsonb)",
                        (json.dumps(asdict(SCOPE) if scope is None else scope), json.dumps(occurrences))).fetchall()


def test_empty_authorized_read_has_db_metadata_and_no_fake_event(password_pg):
    with _connection(password_pg, worker=True) as worker:
        before = worker.execute("select statement_timestamp() as at").fetchone()["at"]
        metadata, rows = _batch(_window(worker))
        after = worker.execute("select statement_timestamp() as at").fetchone()["at"]
        end = datetime.fromisoformat(metadata["read_to"].replace("Z", "+00:00"))
        assert before <= end <= after
        assert end - datetime.fromisoformat(metadata["read_from"].replace("Z", "+00:00")) == timedelta(seconds=720)
        assert end - datetime.fromisoformat(metadata["finalizable_through"].replace("Z", "+00:00")) == timedelta(seconds=120)
        assert (metadata["candidate_count"], metadata["truncated"], metadata["unverifiable_count"],
                metadata["oversized_count"], metadata["error_code"], rows) == (0, False, 0, 0, None, [])
        assert _retained(worker, []) == []


@pytest.mark.parametrize("count", [10000, 10001])
def test_candidate_sentinel_is_counted_before_native_verification(password_pg, count):
    with _connection(password_pg) as admin:
        _seed(admin, count)
        if count == 10001:
            #Invalid sentinel must still truncate; verifier must not run at all.
            admin.execute("delete from sli_agent_receipts where packet_id=md5('password-v2-fixture-10001')::uuid")
            admin.execute("""create or replace function public.read_agent_semantic_source_v190(p_event_id bigint)
                returns jsonb language plpgsql stable as $$ begin raise exception 'sentinel_verifier_must_not_run'; end $$""")
    with _connection(password_pg, worker=True) as worker:
        metadata, rows = _batch(_window(worker))
        assert metadata["candidate_count"] == count
        assert metadata["truncated"] == (count == 10001)
        if count == 10001:
            assert metadata["error_code"] == "password_v2_window_truncated" and rows == []
        else:
            assert metadata["error_code"] is None and len(rows) == count
            assert [row["source_event_id"] for row in rows] == list(range(1, count + 1))
            assert detector.NativeEvent.from_row(SCOPE, rows[-1]).checked().ref.native_id == "10000"


@pytest.mark.parametrize("mutation", [
    "update sli_agent_packet_inbox set imported_at=null",
    "update sli_agent_receipts set receipt='{}'::jsonb",
    "update sli_agent_receipts set envelope='{}'::jsonb",
    "update sli_agent_packet_inbox set envelope=jsonb_set(envelope,'{generation}','\"old\"'); "
    "update sli_agent_receipts r set envelope=i.envelope from sli_agent_packet_inbox i where r.packet_id=i.packet_id",
    "update sli_agent_packet_inbox set envelope=jsonb_set(envelope,'{agent_id}','\"00000000-0000-4000-8000-000000000097\"'); "
    "update sli_agent_receipts r set envelope=i.envelope from sli_agent_packet_inbox i where r.packet_id=i.packet_id",
    "update sli_agent_receipts set module_id='sli.file-audit'",
    "update sli_agent_packet_inbox set event_rows=event_rows||event_rows",
    "update sli_agent_packet_inbox set event_rows=jsonb_set(event_rows,'{0,record_id}','\"wrong\"')",
    "update sli_agent_packet_inbox set event_rows=jsonb_set(event_rows,'{0,xml}','null')",
])
def test_window_native_authority_failure_never_returns_partial_events(password_pg, mutation):
    with _connection(password_pg) as admin:
        _seed(admin)
        admin.execute(mutation)
    with _connection(password_pg, worker=True) as worker:
        metadata, rows = _batch(_window(worker))
        assert metadata["candidate_count"] == 1 and not metadata["truncated"]
        assert metadata["unverifiable_count"] == 1
        assert metadata["error_code"] == "password_v2_native_unavailable" and rows == []


@pytest.mark.parametrize("size,accepted", [(4 * MIB, True), (4 * MIB + 1, False)])
def test_window_actual_utf8_per_event_limit_before_output(password_pg, size, accepted):
    with _connection(password_pg) as admin:
        at = _seed(admin)
        _replace_xml(admin, 1, _xml(at, size=size, unicode=True))
    with _connection(password_pg, worker=True) as worker:
        metadata, rows = _batch(_window(worker))
        assert len(rows) == int(accepted)
        assert metadata["oversized_count"] == int(not accepted)
        assert metadata["error_code"] == (None if accepted else "password_v2_xml_budget_exceeded")
        if accepted:
            assert len(rows[0]["source_xml"].encode("utf-8")) == size


@pytest.mark.parametrize("extra", [0, 1])
def test_window_exact_32mib_or_one_byte_excess_is_all_or_zero(password_pg, extra):
    with _connection(password_pg) as admin:
        at = _seed(admin, 9)
        sizes = [4 * MIB] * 7 + [4 * MIB - 1024, 1024 + extra]
        for native_id, size in enumerate(sizes, 1):
            _replace_xml(admin, native_id, _xml(at, native_id, size=size))
    with _connection(password_pg, worker=True) as worker:
        metadata, rows = _batch(_window(worker))
        assert metadata["candidate_count"] == 9 and metadata["oversized_count"] == 0
        assert metadata["error_code"] == (None if extra == 0 else "password_v2_xml_budget_exceeded")
        assert sum(len(row["source_xml"].encode("utf-8")) for row in rows) == (32 * MIB if extra == 0 else 0)


@pytest.mark.parametrize("dimension,value", [
    ("installation_id", "00000000-0000-4000-8000-000000000097"),
    ("plugin_id", "sli.file-audit"), ("source_instance_id", "other"),
    ("source_generation", "old"), ("collection_scope_id", "other"),
])
def test_every_scope_dimension_is_authorized_even_for_empty_reads(password_pg, dimension, value):
    import psycopg

    scope = asdict(SCOPE) | {dimension: value}
    with _connection(password_pg, worker=True) as worker:
        for reader in (lambda: _window(worker, scope), lambda: _retained(worker, [], scope)):
            with pytest.raises(psycopg.Error) as rejected:
                reader()
            assert rejected.value.sqlstate in {"42501", "22023"}


@pytest.mark.parametrize("field,value", [("principal_oid", 0), ("principal_name", "not-the-login")])
def test_binding_requires_both_oid_and_name(password_pg, field, value):
    import psycopg
    from psycopg import sql

    with _connection(password_pg) as admin:
        admin.execute(sql.SQL("update finding_evidence_source_bindings set {}=%s where plugin_id='sli.windows.ad-dc'")
                      .format(sql.Identifier(field)), (value,))
    with _connection(password_pg, worker=True) as worker:
        for reader in (lambda: _window(worker), lambda: _retained(worker, [])):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                reader()


def test_set_role_and_caller_guc_cannot_borrow_login_binding(password_pg):
    import psycopg

    with _connection(password_pg) as unbound:
        unbound.execute("set role adlog_semantic_worker")
        unbound.execute("select set_config('sli.principal_name',%s,false)", (password_pg[1],))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            _window(unbound)


def test_dropped_recreated_login_cannot_reuse_old_oid_binding(password_pg):
    import psycopg
    from psycopg import sql

    with _connection(password_pg) as admin:
        name = sql.Identifier(password_pg[1])
        admin.execute(sql.SQL("drop role {}").format(name))
        admin.execute(sql.SQL("create role {} login").format(name))
        admin.execute(sql.SQL("grant adlog_semantic_worker to {}").format(name))
    with _connection(password_pg, worker=True) as worker:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            _window(worker)


def test_window_uses_db_horizon_families_bound_source_and_stable_order(password_pg):
    with _connection(password_pg) as admin:
        now = admin.execute("select statement_timestamp() as at").fetchone()["at"]
        for native_id, second in enumerate([-721, -719, 5, -1, -1, -300, -300], 1):
            _seed(admin, at=now + timedelta(seconds=second), start=native_id)
        admin.execute("update events_v2_core set event_id=4624 where id=6")
        admin.execute("update events_v2_core set log_source_id=8 where id=7")
    with _connection(password_pg, worker=True) as worker:
        metadata, rows = _batch(_window(worker))
        assert metadata["error_code"] is None and metadata["candidate_count"] == 3
        assert [row["source_event_id"] for row in rows] == [2, 4, 5]
        for row in rows:
            assert detector.NativeEvent.from_row(SCOPE, row).checked().ref.sha256 == f'{row["source_event_id"]:064x}'


def test_worker_only_gets_scoped_function_access(password_pg):
    import psycopg

    with _connection(password_pg, worker=True) as worker:
        for table in ("events_v2_core", "raw_log_files", "sli_agent_packet_inbox", "sli_agent_receipts",
                      "finding_evidence_source_bindings"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                worker.execute("select * from public." + table + " limit 0")
    with _connection(password_pg) as admin:
        for signature in ("read_default_password_window_v2(jsonb)", "read_password_retained_proof_v2(jsonb,jsonb)"):
            for role in ("adlog_user", "adlog_storage_worker"):
                assert not admin.execute("select has_function_privilege(%s,%s,'EXECUTE') as allowed",
                                         (role, "public." + signature)).fetchone()["allowed"]


def _native_row(admin, native_id=1):
    return admin.execute("""select id as source_event_id,event_id,time_created_utc as occurred_at_utc,
        encode(normalized_hash,'hex') as sha256,
        public.read_agent_semantic_source_v190(id)#>>'{event_row,xml}' as source_xml
        from public.events_v2_core where id=%s""", (native_id,)).fetchone()


def test_retained_actual_native_pass_proves_root_and_590s_continuations(password_pg):
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with _connection(password_pg) as admin:
        for native_id, second in enumerate([*range(10), 599, 1189, 1779], 1):
            _seed(admin, at=base + timedelta(seconds=second), start=native_id)
        originals = [detector.NativeEvent.from_row(SCOPE, _native_row(admin, native_id)).checked()
                     for native_id in range(1, 14)]
    rule = detector.Rule(SCOPE, "brute")
    first = detector.advance(rule, detector.State(), originals[:10], now=base + timedelta(seconds=200))
    chain = list(first.emissions)
    assert len(chain) == 1
    state = detector.State.from_document(first.state.document)
    for index, native in enumerate(originals[10:], 10):
        proposal = detector.advance(rule, state, (native,), now=native.at + timedelta(seconds=120),
                                    history=chain, retained=originals[:index + 1])
        assert len(proposal.emissions) == 1
        chain.extend(proposal.emissions)
        state = detector.State.from_document(proposal.state.document)
    witnesses = [asdict(witness) for emission in chain for witness in emission.occurrences]
    for witness in witnesses:
        witness["at"] = witness["at"].isoformat()
    with _connection(password_pg, worker=True) as worker:
        retained = _retained(worker, witnesses)
        assert [row["occurrence_index"] for row in retained] == list(range(1, len(witnesses) + 1))
        checked = [detector.NativeEvent.from_row(SCOPE, row).checked() for row in retained]
        assert detector.verify_chain(rule, chain, checked).ref_occurrences == len(witnesses)
        assert all(row["xml_bytes"] == len(row["source_xml"].encode("utf-8")) and
                   row["xml_sha256"] == sha256(row["source_xml"].encode("utf-8")).hexdigest() for row in retained)
    #Deleting an intermediate blocks the entire retained read although later
    #native endpoints and the original qualifying proof remain available.
    with _connection(password_pg) as admin:
        admin.execute("delete from sli_agent_receipts where packet_id=md5('password-v2-fixture-11')::uuid")
    import psycopg
    with _connection(password_pg, worker=True) as worker:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="password_v2_retained_unavailable"):
            _retained(worker, witnesses)


@pytest.mark.parametrize("mutation", ["content", "length", "digest", "normalized", "time", "scope", "expired"])
def test_retained_refs_need_current_actual_content_and_commitment(password_pg, mutation):
    import psycopg

    with _connection(password_pg) as admin:
        _seed(admin)
        occurrence = _occurrence(_native_row(admin))
        if mutation == "content":
            #The old normalized hash still resolves; changed XML must not pass.
            _replace_xml(admin, 1, _native_row(admin)["source_xml"].replace("0xc000006a", "0xc0000064"))
        elif mutation == "length":
            occurrence["xml_bytes"] += 1
        elif mutation == "digest":
            occurrence["xml_sha256"] = "a" * 64
        elif mutation == "normalized":
            occurrence["ref"]["sha256"] = "b" * 64
        elif mutation == "time":
            occurrence["at"] = (datetime.fromisoformat(occurrence["at"]) + timedelta(seconds=1)).isoformat()
        elif mutation == "scope":
            occurrence["ref"]["scope"]["source_generation"] = "old"
        else:
            admin.execute("update sli_agent_packet_inbox set imported_at=null")
    with _connection(password_pg, worker=True) as worker:
        with pytest.raises(psycopg.Error) as rejected:
            _retained(worker, [occurrence])
        assert rejected.value.sqlstate in {"42501", "22023"}


@pytest.mark.parametrize("count", [10000, 10001])
def test_retained_count_budget_counts_occurrences_not_distinct_ids(password_pg, count):
    import psycopg

    with _connection(password_pg) as admin:
        _seed(admin)
        occurrence = _occurrence(_native_row(admin))
    with _connection(password_pg, worker=True) as worker:
        if count == 10000:
            rows = _retained(worker, [occurrence] * count)
            assert len(rows) == count and {row["source_event_id"] for row in rows} == {1}
        else:
            with pytest.raises(psycopg.errors.ProgramLimitExceeded, match="password_v2_proof_budget_exceeded"):
                _retained(worker, [occurrence] * count)


@pytest.mark.parametrize("extra", [0, 1])
def test_retained_repeated_anchor_byte_cost_is_exact_32mib_or_whole_reject(password_pg, extra):
    import psycopg

    with _connection(password_pg) as admin:
        at = _seed(admin, 3)
        sizes = [4 * MIB, 4 * MIB - 1024, 1024 + extra]
        for native_id, size in enumerate(sizes, 1):
            _replace_xml(admin, native_id, _xml(at, native_id, size=size, unicode=True))
        refs = [_occurrence(_native_row(admin, native_id)) for native_id in range(1, 4)]
    occurrences = [refs[0]] * 7 + refs[1:]
    with _connection(password_pg, worker=True) as worker:
        if extra:
            with pytest.raises(psycopg.errors.ProgramLimitExceeded, match="password_v2_proof_budget_exceeded"):
                _retained(worker, occurrences)
        else:
            rows = _retained(worker, occurrences)
            assert len(rows) == 9 and sum(row["xml_bytes"] for row in rows) == 32 * MIB


def test_retained_rejects_conflicting_commitments_for_same_native_id(password_pg):
    import psycopg

    with _connection(password_pg) as admin:
        _seed(admin)
        first = _occurrence(_native_row(admin))
    second = deepcopy(first)
    second["xml_sha256"] = "c" * 64
    with _connection(password_pg, worker=True) as worker:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            _retained(worker, [first, second])


def test_retained_actual_per_event_oversize_is_rejected_even_with_matching_commitment(password_pg):
    import psycopg

    with _connection(password_pg) as admin:
        at = _seed(admin)
        _replace_xml(admin, 1, _xml(at, size=4 * MIB + 1))
        occurrence = _occurrence(_native_row(admin))
    with _connection(password_pg, worker=True) as worker:
        with pytest.raises(psycopg.errors.ProgramLimitExceeded, match="password_v2_proof_budget_exceeded"):
            _retained(worker, [occurrence])


def test_window_mixed_good_unavailable_and_oversize_has_no_partial_xml(password_pg):
    with _connection(password_pg) as admin:
        at = _seed(admin, 3)
        _replace_xml(admin, 2, _xml(at, 2, size=4 * MIB + 1))
        admin.execute("delete from sli_agent_receipts where packet_id=md5('password-v2-fixture-3')::uuid")
    with _connection(password_pg, worker=True) as worker:
        metadata, rows = _batch(_window(worker))
        #First fatal oversize stops before the later unavailable receipt.
        assert metadata["unverifiable_count"] == 0 and metadata["oversized_count"] == 1
        assert metadata["native_checked_count"] == 2 and metadata["native_checks_complete"] is False
        assert metadata["error_code"] == "password_v2_xml_budget_exceeded" and rows == []


@pytest.mark.parametrize("scope", [None, [], {}, {**asdict(SCOPE), "verified": True},
                                 {**asdict(SCOPE), "source_instance_id": " fixture-password"},
                                 {**asdict(SCOPE), "installation_id": "invalid"}])
def test_malformed_scope_is_fixed_error_and_not_successful_empty(password_pg, scope):
    import psycopg

    with _connection(password_pg, worker=True) as worker:
        #Pass JSON null literally; helper None otherwise means default scope.
        with pytest.raises(psycopg.errors.InvalidParameterValue, match="password_v2_arguments_invalid"):
            worker.execute("select * from read_default_password_window_v2(%s::jsonb)", (json.dumps(scope),))


@pytest.mark.parametrize("occurrences", [None, {}, [None], [{"verified": True}],
    [{"ref": {"storage_kind": "core_event", "native_id": "01", "sha256": "a" * 64, "scope": asdict(SCOPE)},
      "at": "2026-01-01T00:00:00Z", "xml_sha256": "b" * 64, "xml_bytes": 1}]])
def test_retained_rejects_malformed_documents_without_database_details(password_pg, occurrences):
    import psycopg

    with _connection(password_pg, worker=True) as worker:
        with pytest.raises(psycopg.errors.InvalidParameterValue, match="password_v2_arguments_invalid"):
            _retained(worker, occurrences)


def test_index_supports_bounded_scoped_time_candidates(password_pg):
    with _connection(password_pg) as admin:
        at = _seed(admin, 1000)
        #Disabling sequential scans here tests support by the specific index;
        #it does not claim this tiny fixture predicts the production cost plan.
        admin.execute("set enable_seqscan=off")
        plan = admin.execute("""explain(format json) select id from public.events_v2_core
            where log_source_id=7 and event_id in (4625,4771,4776)
              and time_created_utc between %s and %s order by time_created_utc,id limit 10001""",
            (at - timedelta(seconds=1), at + timedelta(seconds=1))).fetchone()["QUERY PLAN"]
        index_names = {row["indexname"] for row in admin.execute("""select indexname from pg_indexes
            where schemaname='public' and tablename='events_v2_core' and indexdef like '%log_source_id, time_created_utc, id%'
              and indexdef like '%WHERE%'""").fetchall()}
        assert index_names and any(name in json.dumps(plan) for name in index_names)


@pytest.mark.parametrize("guard", ["missing", "wrong_name", "occupied", "owner"])
def test_migration_guard_leaves_no_partial_objects(password_base_pg, guard):
    import psycopg

    assert PATH.exists(), "B1 migration273 is missing"
    with psycopg.connect(password_base_pg, autocommit=True) as conn:
        if guard == "missing":
            conn.execute("delete from schema_migrations where version=272")
        elif guard == "wrong_name":
            conn.execute("update schema_migrations set name='wrong' where version=272")
        elif guard == "occupied":
            conn.execute("insert into schema_migrations values(273,'occupied')")
        else:
            conn.execute("set session authorization adlog_user")
        with pytest.raises(psycopg.errors.RaiseException, match="migration 273 prerequisites failed"):
            conn.execute(PATH.read_text("utf-8-sig"))
        conn.execute("rollback")
        conn.execute("reset session authorization")
        assert conn.execute("select to_regprocedure('public.read_default_password_window_v2(jsonb)')").fetchone()[0] is None
        assert conn.execute("select to_regprocedure('public.read_password_retained_proof_v2(jsonb,jsonb)')").fetchone()[0] is None
        assert not conn.execute("""select 1 from pg_indexes where tablename='events_v2_core'
            and indexdef like '%log_source_id, time_created_utc, id%' and indexdef like '%WHERE%'""").fetchall()


def test_migration_reapply_fails_without_changing_existing_readers(password_pg):
    import psycopg

    assert PATH.exists(), "B1 migration273 is missing"
    with _connection(password_pg) as admin:
        before = admin.execute("select pg_get_functiondef('public.read_default_password_window_v2(jsonb)'::regprocedure) as body").fetchone()["body"]
        with pytest.raises(psycopg.Error):
            admin.execute(PATH.read_text("utf-8-sig"))
        admin.execute("rollback")
        assert admin.execute("select pg_get_functiondef('public.read_default_password_window_v2(jsonb)'::regprocedure) as body").fetchone()["body"] == before
    with _connection(password_pg, worker=True) as worker:
        assert _batch(_window(worker))[0]["error_code"] is None


def test_migration_failure_after_ddl_rolls_back_functions_index_and_ledger(password_base_pg):
    import psycopg

    assert PATH.exists(), "B1 migration273 is missing"
    migration = PATH.read_text("utf-8-sig")
    marker = "insert into public.schema_migrations(version,name) values(273,'password_attacks_v2');"
    assert marker in migration
    with psycopg.connect(password_base_pg, autocommit=True) as conn:
        with pytest.raises(psycopg.errors.DivisionByZero):
            conn.execute(migration.replace(marker, "select 1/0;\n" + marker))
        conn.execute("rollback")
        assert conn.execute("select to_regprocedure('public.read_default_password_window_v2(jsonb)')").fetchone()[0] is None
        assert conn.execute("select to_regclass('public.idx_password_v2_source_time')").fetchone()[0] is None
        assert conn.execute("select count(*) from schema_migrations where version=273").fetchone()[0] == 0


def test_actual_266_index_with_269_270_271_272_fixture_markers_and_273_ledger(password_pg):
    with _connection(password_pg) as admin:
        rows = admin.execute("select version,name from schema_migrations where version between 265 and 273 order by version").fetchall()
        assert rows == [
            {"version": 265, "name": "file_acl_semantic_bridge"},
            {"version": 266, "name": "file_audit_source_lookup_index"},
            {"version": 269, "name": "file_audit_canonical_aggregation"},
            {"version": 270, "name": "account_decoy_source_prefilter"},
            {"version": 271, "name": "account_watch_source_prefilter"},
            {"version": 272, "name": "file_audit_assignment_policy"},
            {"version": 273, "name": "password_attacks_v2"},
        ]
        index = admin.execute("""select indisvalid,indisready from pg_index
            where indexrelid='sli_plugin_file_audit.file_audit_source_lookup_index'::regclass""").fetchone()
        assert index == {"indisvalid": True, "indisready": True}
