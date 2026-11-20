from __future__ import annotations

"""Regression coverage for the psycopg3 tuple/list ANY(%s) adaptation defect.

Production discovered that ``event_ids = tuple(sorted(EVENT_IDS))`` passed as
a bind parameter for ``column = any(%s)`` raises
``psycopg.errors.InvalidTextRepresentation`` (malformed array literal),
because this project's psycopg3 configuration adapts a Python ``tuple`` to
PostgreSQL row-value syntax ``(a,b,c)``, not array syntax ``{a,b,c}`` -- only
a ``list`` adapts to an array.  A fake cursor that only inspects the Python
object passed to ``execute`` cannot see this: the defect is in the real
driver/server contract, so this test exercises a real disposable PostgreSQL
database with the real psycopg3 driver, exactly like the migration 087
disposable acceptance proof.
"""

import os
from datetime import datetime, timedelta, timezone

import pytest

from tests.postgres_integration_guard import assert_disposable_database

ACCESS = {
    "platform_owner": True,
    "capabilities": ["events.view"],
    "capability_policies": [],
    "reports": [
        {
            "report_key": report_key,
            "allowed": True,
            "grants": [{"allowed_actions": ["view"], "scope": {"kind": "all"}}],
        }
        for report_key in ("vpn.audit", "ad.state")
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
        "insert into forests(name) values ('hotfix-forest') "
        "on conflict(name) do update set name=excluded.name returning id"
    )
    forest_id = cur.fetchone()["id"]
    cur.execute(
        "insert into domains(forest_id,fqdn) values (%s,'hotfix.example.invalid') "
        "on conflict(forest_id,fqdn) do update set fqdn=excluded.fqdn returning id",
        (forest_id,),
    )
    domain_id = cur.fetchone()["id"]
    cur.execute(
        "insert into servers(domain_id,hostname,role) values (%s,'dc1-hotfix','domain_controller') "
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
    cur.execute(
        "insert into storage_v2_computer(value) values ('dc1-hotfix') "
        "on conflict(value) do update set value=excluded.value returning id"
    )
    computer_id = cur.fetchone()["id"]
    return {
        "domain_id": domain_id,
        "server_id": server_id,
        "channel_id": channel_id,
        "provider_id": provider_id,
        "computer_id": computer_id,
    }


def _insert_event(cur, *, event_db_id: int, ids: dict[str, int], event_id: int, occurred: datetime, **extra) -> None:
    cur.execute(
        """
        insert into events_v2_core(
            id,server_id,domain_id,log_source_id,event_record_id,event_id,
            provider_id,channel_id,computer_id,time_created_utc,
            subject_user_sid,subject_user_name,target_user_sid,target_user_name,
            normalized_at,normalized_hash,source_core_sha256
        ) values (%s,%s,%s,1,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now(),%s,%s)
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
            ids["computer_id"],
            occurred,
            extra.get("subject_user_sid", "S-1-5-21-100-500"),
            extra.get("subject_user_name", "hotfix-admin"),
            extra.get("target_user_sid", "S-1-5-21-100-1001"),
            extra.get("target_user_name", "hotfix-target"),
            bytes([event_id % 251]) * 32,
            bytes([(event_id + 1) % 251]) * 32,
        ),
    )


@pytest.mark.postgres_integration
def test_tuple_parameter_fails_real_postgresql_any_array_contract() -> None:
    """RED: the exact removed pattern (tuple bound to ANY(%s)) fails for real."""

    psycopg, connect = _connect_or_skip()
    with connect() as conn, conn.cursor() as cur:
        assert_disposable_database(conn)
        event_ids_tuple = tuple(sorted({4728, 4729, 4732, 4733, 4756, 4757}))
        with pytest.raises(psycopg.errors.InvalidTextRepresentation):
            cur.execute("select 1 where 4728 = any(%s)", (event_ids_tuple,))


@pytest.mark.postgres_integration
def test_list_parameter_satisfies_real_postgresql_any_array_contract() -> None:
    """GREEN counterpart: the fixed pattern (list) adapts to a real array."""

    _, connect = _connect_or_skip()
    with connect() as conn, conn.cursor() as cur:
        assert_disposable_database(conn)
        event_ids_list = sorted({4728, 4729, 4732, 4733, 4756, 4757})
        cur.execute("select (4728 = any(%s)) as matched", (event_ids_list,))
        assert cur.fetchone()["matched"] is True


@pytest.mark.postgres_integration
@pytest.mark.postgres_historical(371, "password_domain_auto")
def test_fixed_read_paths_survive_real_psycopg3_adaptation() -> None:
    """The three legacy report functions read seeded rows using real psycopg3."""

    from server.sli.reports.ad_account_state_reporting import (
        get_ad_account_change_history,
    )
    from server.sli.reports.ad_group_membership_reporting import (
        get_ad_group_membership_history,
    )
    from server.sli.reports.windows_authentication_reporting import (
        get_windows_authentication_report,
    )

    _, connect = _connect_or_skip()
    occurred = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
    with connect() as conn, conn.cursor() as cur:
        assert_disposable_database(conn)
        ids = _seed_fixture(cur)
        _insert_event(cur, event_db_id=910001, ids=ids, event_id=4728, occurred=occurred)
        cur.execute(
            "insert into event_facts_v2(event_id,membership_member_sid,membership_member_name,source_facts_sha256) "
            "values (%s,%s,%s,%s)",
            (910001, "S-1-5-21-100-2002", "hotfix-member", bytes([1]) * 32),
        )
        _insert_event(cur, event_db_id=910002, ids=ids, event_id=4720, occurred=occurred)
        cur.execute(
            "insert into event_facts_v2(event_id,source_facts_sha256) values (%s,%s)",
            (910002, bytes([2]) * 32),
        )
        _insert_event(cur, event_db_id=910003, ids=ids, event_id=4723, occurred=occurred)
        cur.execute(
            "insert into event_facts_v2(event_id,source_facts_sha256) values (%s,%s)",
            (910003, bytes([3]) * 32),
        )
        _insert_event(cur, event_db_id=910004, ids=ids, event_id=4624, occurred=occurred)
        cur.execute(
            "insert into event_facts_v2(event_id,logon_type,result_code,source_facts_sha256) values (%s,%s,%s,%s)",
            (910004, "3", "0x0", bytes([4]) * 32),
        )
        domain_id = ids["domain_id"]

    time_from = (occurred - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    time_to = (occurred + timedelta(hours=1)).isoformat().replace("+00:00", "Z")

    membership = get_ad_group_membership_history(
        ACCESS, source_domain_id=domain_id, time_from=time_from, time_to=time_to
    )
    assert membership["state"] == "available"
    assert [item["event_id"] for item in membership["items"]] == [4728]

    account_changes = get_ad_account_change_history(
        ACCESS, source_domain_id=domain_id, time_from=time_from, time_to=time_to
    )
    assert account_changes["state"] == "available"
    observed_event_ids = sorted(item["event_id"] for item in account_changes["items"])
    assert observed_event_ids == [4720, 4723]
    password_attempts = [
        item for item in account_changes["items"] if item["event_id"] == 4723
    ]
    assert password_attempts and password_attempts[0]["change"]["kind"] == "password_change_attempt"

    windows_auth = get_windows_authentication_report(
        ACCESS, source_domain_id=domain_id, time_from=time_from, time_to=time_to
    )
    assert windows_auth["state"] == "available"
    assert [item["event_id"] for item in windows_auth["items"]] == [4624]
