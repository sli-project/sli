from __future__ import annotations

"""Regression coverage for the NPS 6272/6273 authorization-timeline SQL defect.

`_read_vpn_authorization_timeline_data`'s coverage-witness query had a stray
opening paren before ``exists(`` (``select (exists( ... ) as
history_event_present``), which PostgreSQL rejects as a syntax error before
the query ever runs -- no fake cursor or compose-layer test can see this,
since the defect is in the SQL text itself. This exercises the real
function against a real disposable PostgreSQL database with the real
psycopg3 driver, same convention as the sibling ANY(%s) hotfix.
"""

import os
from datetime import datetime, timedelta, timezone

import pytest

from tests.postgres_integration_guard import assert_disposable_database

ACCESS = {
    "platform_owner": True,
    "capabilities": ["vpn.sessions.view"],
    "capability_policies": [],
    "reports": [
        {
            "report_key": "vpn.audit",
            "allowed": True,
            "grants": [{"allowed_actions": ["view"], "scope": {"kind": "all"}}],
        }
    ],
}


def _connect_or_skip():
    dsn = (os.environ.get("ADLOG_TEST_PG_DSN") or "").strip()
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN is not configured for isolated PostgreSQL integration tests")
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    def connect():
        return psycopg.connect(dsn, row_factory=dict_row)

    return psycopg, connect


def _seed_fixture(cur) -> dict[str, int]:
    cur.execute(
        "insert into event_catalog_revisions(version) values ('pending-backfill') "
        "on conflict(version) do update set version=excluded.version"
    )
    cur.execute(
        "insert into forests(name) values ('nps-hotfix-forest') "
        "on conflict(name) do update set name=excluded.name returning id"
    )
    forest_id = cur.fetchone()["id"]
    cur.execute(
        "insert into domains(forest_id,fqdn) values (%s,'nps-hotfix.example.invalid') "
        "on conflict(forest_id,fqdn) do update set fqdn=excluded.fqdn returning id",
        (forest_id,),
    )
    domain_id = cur.fetchone()["id"]
    cur.execute(
        "insert into servers(domain_id,hostname,role) values (%s,'nps1-hotfix','nps') "
        "on conflict(domain_id,hostname) do update set role=excluded.role returning id",
        (domain_id,),
    )
    server_id = cur.fetchone()["id"]
    cur.execute(
        "insert into storage_v2_channel(value) values ('Security') "
        "on conflict(value) do update set value=excluded.value returning id"
    )
    channel_id = cur.fetchone()["id"]
    cur.execute(
        "insert into storage_v2_provider(value) values ('Microsoft-Windows-Security-Auditing') "
        "on conflict(value) do update set value=excluded.value returning id"
    )
    provider_id = cur.fetchone()["id"]
    return {
        "domain_id": domain_id,
        "server_id": server_id,
        "channel_id": channel_id,
        "provider_id": provider_id,
    }


def _insert_event(cur, *, event_db_id: int, ids: dict[str, int], event_id: int, occurred: datetime) -> None:
    cur.execute(
        """
        insert into events_v2_core(
            id,server_id,domain_id,log_source_id,event_record_id,event_id,
            provider_id,channel_id,time_created_utc,subject_user_sid,ip_address,
            normalized_at,normalized_hash,source_core_sha256
        ) values (%s,%s,%s,1,%s,%s,%s,%s,%s,%s,%s,now(),%s,%s)
        on conflict (id) do update set event_id=excluded.event_id
        """,
        (
            event_db_id,
            ids["server_id"],
            ids["domain_id"],
            event_db_id,
            event_id,
            ids["provider_id"],
            ids["channel_id"],
            occurred,
            "S-1-5-21-100-2001",
            "198.51.100.10",
            bytes([event_id % 251]) * 32,
            bytes([(event_id + 1) % 251]) * 32,
        ),
    )


@pytest.mark.postgres_integration
@pytest.mark.postgres_historical(371, "password_domain_auto")
def test_authorization_timeline_coverage_query_reaches_real_postgresql() -> None:
    """RED/GREEN: the coverage-witness query (the exact defect site) must execute."""

    from server.sli.reports.vpn_connections_reporting import _read_vpn_authorization_timeline_data

    _, connect = _connect_or_skip()
    occurred = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
    with connect() as conn, conn.cursor() as cur:
        assert_disposable_database(conn)
        ids = _seed_fixture(cur)
        _insert_event(cur, event_db_id=920001, ids=ids, event_id=6272, occurred=occurred)
        _insert_event(cur, event_db_id=920002, ids=ids, event_id=6273, occurred=occurred)
        domain_id = ids["domain_id"]

    period_start = occurred - timedelta(hours=1)
    period_end = occurred + timedelta(hours=1)

    events, identities, coverage = _read_vpn_authorization_timeline_data(
        domain_id=domain_id, period_start=period_start, period_end=period_end
    )
    assert [event["event_id"] for event in events] == [6272, 6273]
    assert coverage["history_event_present"] is True
    assert coverage["window_success_6272_count"] == 1
    assert coverage["window_failed_6273_count"] == 1


@pytest.mark.postgres_integration
@pytest.mark.postgres_historical(371, "password_domain_auto")
def test_authorization_timeline_empty_window_is_honest_and_uncorrelated() -> None:
    """GREEN: an empty window stays honestly empty; no NPS<->Accounting join appears."""

    from server.sli.reports.vpn_connections_reporting import get_vpn_authorization_timeline

    _, connect = _connect_or_skip()
    occurred = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
    with connect() as conn, conn.cursor() as cur:
        assert_disposable_database(conn)
        ids = _seed_fixture(cur)
        # Seed a history witness far outside the queried window, and zero
        # events inside it, to prove the window stays honestly empty and the
        # history-presence witness is independent of the windowed counts.
        _insert_event(
            cur, event_db_id=920003, ids=ids, event_id=6272,
            occurred=occurred - timedelta(days=10),
        )
        domain_id = ids["domain_id"]

    def iso(dt: datetime) -> str:
        return dt.isoformat().replace("+00:00", "Z")

    result = get_vpn_authorization_timeline(
        ACCESS,
        source_domain_id=domain_id,
        time_from=iso(occurred - timedelta(hours=1)),
        time_to=iso(occurred + timedelta(hours=1)),
    )
    assert result["items"] == []
    assert "session" not in result
    assert "accounting" not in result
