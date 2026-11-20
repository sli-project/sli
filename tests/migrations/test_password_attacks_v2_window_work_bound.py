"""Bound native-window work at the first failure; real190/264 authority delegates."""
from contextlib import contextmanager
from dataclasses import asdict

import pytest

from tests.migrations.test_password_attacks_v2_migration import (
    MIB, SCOPE, _batch, _connection, _replace_xml, _seed, _window, _xml,
    acl_pg as acl_pg, native_pg as native_pg,
    password_base_pg as password_base_pg, password_pg as password_pg,
)

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]
SNAPSHOT = """select oid,proowner,proacl::text as acl,pg_get_functiondef(oid) as definition
    from pg_proc where oid='public.read_agent_semantic_source_v190(bigint)'::regprocedure"""


@contextmanager
def _count_native(admin, login):
    """Disposable owner instrumentation; delegate unchanged current190, restore finally."""
    from psycopg import sql

    before = admin.execute(SNAPSHOT).fetchone()
    admin.execute("create temporary sequence fixture_password_window_reads minvalue 0 start 0")
    admin.execute("grant usage on sequence pg_temp.fixture_password_window_reads to adlog_storage_owner")
    admin.execute("alter function public.read_agent_semantic_source_v190(bigint) rename to fixture_window_original_v190")
    try:
        admin.execute("""create function public.read_agent_semantic_source_v190(p_event_id bigint) returns jsonb
            language plpgsql volatile security definer set search_path=pg_catalog,pg_temp as $$
            begin
                perform nextval('pg_temp.fixture_password_window_reads');
                return public.fixture_window_original_v190(p_event_id);
            end $$;
            alter function public.read_agent_semantic_source_v190(bigint) owner to adlog_storage_owner;
            revoke all on function public.read_agent_semantic_source_v190(bigint)
                from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
            grant execute on function public.read_agent_semantic_source_v190(bigint) to adlog_semantic_worker;
        """)
        original = admin.execute("""select oid,proowner,proacl::text as acl from pg_proc
            where oid='public.fixture_window_original_v190(bigint)'::regprocedure""").fetchone()
        assert original == {k: before[k] for k in ("oid", "proowner", "acl")}
        admin.execute(sql.SQL("set session authorization {}").format(sql.Identifier(login)))
        admin.execute("set role adlog_semantic_worker")
        yield admin
    finally:
        admin.execute("reset session authorization")
        admin.execute("reset role")
        admin.execute("drop function if exists public.read_agent_semantic_source_v190(bigint)")
        admin.execute("alter function public.fixture_window_original_v190(bigint) rename to read_agent_semantic_source_v190")
        assert admin.execute(SNAPSHOT).fetchone() == before


def _read_count(admin):
    counter = admin.execute("select last_value,is_called from pg_temp.fixture_password_window_reads").fetchone()
    return counter["last_value"] + 1 if counter["is_called"] else 0


def _failed(metadata, rows, *, candidates, checked, error, unavailable=0, oversized=0):
    assert rows == []
    assert metadata["candidate_count"] == candidates
    assert metadata["native_checked_count"] == checked
    assert metadata["native_checks_complete"] is (checked == candidates)
    assert metadata["unverifiable_count"] == unavailable
    assert metadata["oversized_count"] == oversized
    assert metadata["error_code"] == error
    assert metadata["truncated"] is False


@pytest.mark.parametrize("position", [1, 3])
@pytest.mark.parametrize("failure", ["receipt", "type", "binding"])
def test_first_native_failure_stops_before_untouched_suffix(password_pg, position, failure):
    with _connection(password_pg) as admin:
        _seed(admin, 5)
        if failure == "receipt":
            admin.execute("delete from sli_agent_receipts where packet_id=md5('password-v2-fixture-'||%s::text)::uuid", (position,))
        elif failure == "type":
            admin.execute("""update sli_agent_packet_inbox set event_rows=jsonb_set(event_rows,'{0,xml}','17'::jsonb)
                where packet_id=md5('password-v2-fixture-'||%s::text)::uuid""", (position,))
        else:
            #190 can still read this row, but264 must reject its generation binding.
            admin.execute("""update sli_agent_packet_inbox set envelope=jsonb_set(envelope,'{generation}','"wrong"')
                where packet_id=md5('password-v2-fixture-'||%s::text)::uuid;
                """, (position,))
            admin.execute("update sli_agent_receipts r set envelope=i.envelope from sli_agent_packet_inbox i where r.packet_id=i.packet_id")
        with _count_native(admin, password_pg[1]) as worker:
            metadata, rows = _batch(_window(worker))
        # Assert actual delegated calls before additive metadata: clean behavioral RED.
        assert _read_count(admin) == position
        _failed(metadata, rows, candidates=5, checked=position,
                error="password_v2_native_unavailable", unavailable=1)


@pytest.mark.parametrize("position", [1, 3])
def test_first_oversize_stops_without_reading_later_unavailable_rows(password_pg, position):
    with _connection(password_pg) as admin:
        at = _seed(admin, 5)
        _replace_xml(admin, position, _xml(at, position, size=4 * MIB + 1))
        admin.execute("delete from sli_agent_receipts where packet_id=md5('password-v2-fixture-5')::uuid")
        with _count_native(admin, password_pg[1]) as worker:
            metadata, rows = _batch(_window(worker))
        assert _read_count(admin) == position
        _failed(metadata, rows, candidates=5, checked=position,
                error="password_v2_xml_budget_exceeded", oversized=1)


def test_cumulative_overflow_lookahead_stops_before_tenth_native_read(password_pg):
    with _connection(password_pg) as admin:
        at = _seed(admin, 10)
        for native_id in range(1, 9):
            _replace_xml(admin, native_id, _xml(at, native_id, size=4 * MIB))
        _replace_xml(admin, 9, _xml(at, 9, size=1024))
        admin.execute("delete from sli_agent_receipts where packet_id=md5('password-v2-fixture-10')::uuid")
        with _count_native(admin, password_pg[1]) as worker:
            metadata, rows = _batch(_window(worker))
        assert _read_count(admin) == 9
        _failed(metadata, rows, candidates=10, checked=9,
                error="password_v2_xml_budget_exceeded")


@pytest.mark.parametrize("count", [0, 3])
def test_empty_and_valid_windows_complete_exact_native_work(password_pg, count):
    with _connection(password_pg) as admin:
        if count:
            _seed(admin, count)
        with _count_native(admin, password_pg[1]) as worker:
            metadata, rows = _batch(_window(worker))
        assert _read_count(admin) == count
        assert metadata["native_checked_count"] == metadata["candidate_count"] == count
        assert metadata["native_checks_complete"] is True
        assert metadata["error_code"] is None and not metadata["truncated"]
        assert metadata["unverifiable_count"] == metadata["oversized_count"] == 0
        assert len(rows) == count
        assert [row["source_event_id"] for row in rows] == list(range(1, count + 1))
        assert all(isinstance(row["source_xml"], str) and row["source_xml"] for row in rows)


def test_last_candidate_failure_is_complete_but_still_all_zero_error(password_pg):
    with _connection(password_pg) as admin:
        _seed(admin, 2)
        admin.execute("delete from sli_agent_receipts where packet_id=md5('password-v2-fixture-2')::uuid")
        with _count_native(admin, password_pg[1]) as worker:
            metadata, rows = _batch(_window(worker))
        assert _read_count(admin) == 2
        _failed(metadata, rows, candidates=2, checked=2,
                error="password_v2_native_unavailable", unavailable=1)


def test_sentinel_counts_candidates_but_performs_zero_native_checks(password_pg):
    with _connection(password_pg) as admin:
        #Candidate-only sentinel: no packet/XML matrix or10000 native reads.
        admin.execute("""insert into events_v2_core
            select g,4625,7,decode(lpad(to_hex(g),64,'0'),'hex'),g,
                statement_timestamp()-interval '300 seconds',g from generate_series(1,10001) g""")
        with _count_native(admin, password_pg[1]) as worker:
            metadata, rows = _batch(_window(worker))
        assert _read_count(admin) == 0
        assert metadata["candidate_count"] == 10001 and metadata["truncated"] is True
        assert metadata["native_checked_count"] == 0 and metadata["native_checks_complete"] is False
        assert metadata["unverifiable_count"] == metadata["oversized_count"] == 0
        assert metadata["error_code"] == "password_v2_window_truncated" and rows == []


def test_scope_failure_precedes_native_work(password_pg):
    import psycopg

    with _connection(password_pg) as admin:
        _seed(admin, 2)
        with _count_native(admin, password_pg[1]) as worker:
            with pytest.raises(psycopg.errors.InsufficientPrivilege, match="password_v2_source_denied"):
                _window(worker, asdict(SCOPE) | {"source_generation": "other"})
        assert _read_count(admin) == 0