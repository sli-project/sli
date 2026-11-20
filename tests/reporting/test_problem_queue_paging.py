"""T062: group the authorized population before the 50-row queue boundary."""
import json
import os
from dataclasses import replace

import pytest

from server.sli.reporting.v2.reports import security_problems as report
from server.sli.semantic import findings
from server.sli.semantic.problem_groups import QUEUE_COHORT_JOIN, queue_cohorts_cte
from tests.reporting.test_security_problems_v2 import _context


@pytest.fixture(autouse=True)
def no_optional_readers(monkeypatch):
    monkeypatch.setattr(report, "password_coverage_catalog_domains", lambda: [])
    monkeypatch.setattr(report, "linked_cases_for_findings", lambda _: {})


@pytest.mark.parametrize("identity_allowed", [True, False])
def test_every_page_reaches_the_declared_total_and_cursors_keep_scope(monkeypatch, identity_allowed):
    # 149 repeated findings plus 60 distinct ones; a restricted viewer gets 209 originals.
    total = 61 if identity_allowed else 209
    calls = []

    def read(**values):
        calls.append(values)
        end = values["after_id"] or total + 1
        ids = list(range(end - 1, max(0, end - 51), -1))
        return {"state": "available", "items": [{"id": value, "status": "new",
            **({"queue_cursor_id": value, "occurrence_count": 149 if value == 61 else 1,
                "problem_cohort": ["finding", value]} if identity_allowed else {})} for value in ids],
            "has_more": ids[-1] > 1, "summary": [{"status": "new", "count": total}],
            "semantic_runtime": {"findings_state": "active"}}

    monkeypatch.setattr(report, "get_security_problems_data", read)
    context = _context({"population": "open"})
    if not identity_allowed:
        access = context.access
        for grant in access["reports"]:
            for scope in grant["grants"]:
                scope["field_categories"] = ["security"]
    cursor, loaded, occurrences = None, [], 0
    for _ in range(5):
        body = report._query(replace(context, cursor=cursor))
        assert body["filtered_count"] == total
        assert next(metric["value"] for metric in body["metrics"] if metric["key"] == "open") == total
        loaded.extend(row["id"] for row in body["items"])
        occurrences += sum(row.get("occurrence_count", 1) for row in body["items"])
        assert calls[-1]["group_queue"] is identity_allowed
        assert calls[-1]["open_only"] and calls[-1]["page_queue"]
        cursor = body["next_cursor"]
        if not body["has_more"]:
            break
        assert cursor
        with pytest.raises(ValueError, match="invalid_cursor"):
            report._query(replace(context, cursor=cursor, domain_ids=[8]))
        with pytest.raises(ValueError, match="invalid_cursor"):
            report._query(replace(context, cursor=cursor, timezone="Europe/Berlin"))
    assert loaded == list(range(total, 0, -1))
    assert occurrences == 209 and cursor is None


@pytest.mark.parametrize(("params", "open_only"), [
    ({"id": "7"}, False), ({"population": "open"}, True),
    ({"population": "attention"}, False), ({"status": "closed"}, False), ({"risk": "accepted"}, False),
])
def test_detail_keeps_closed_deep_links_and_rechecks_the_selected_population(monkeypatch, params, open_only):
    calls = []
    monkeypatch.setattr(report, "get_security_problems_data", lambda **values: calls.append(values) or {"items": []})
    with pytest.raises(LookupError, match="report_row_not_found"):
        report._detail(_context(params), "7")
    assert calls[0]["finding_id"] == 7 and calls[0]["open_only"] is open_only


def test_grouped_reader_filters_before_aggregation_and_pages_after_it(monkeypatch):
    calls = []
    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(findings, "resolve_storage_route", lambda **_: {"route": "v2"})
    monkeypatch.setattr(findings, "get_findings_refresh_status", lambda **_: {})
    monkeypatch.setattr(findings, "query_rows", lambda sql, params=(): calls.append((sql, params)) or [])
    findings.get_security_problems_data(group_queue=True, open_only=True, after_id=99,
        cohort_timezone="UTC", domain_ids=[7], compact=True)
    rows, summary = calls[:2]
    for sql, params in (rows, summary):
        assert "is_semantic_finding_published_v1(findings.id)" in sql
        assert "semantic_finding_in_domains_v265(findings.id,?::bigint[])" in sql
        assert "not semantic_finding_suppressed" in sql
        assert "'active','review'" in sql
        assert "findings.actor,findings.target" in sql
        assert "partition by cohort.key" in sql
        assert params[:2] == ("UTC", [7])
    assert "queue_groups.queue_cursor_id < ?" in rows[0]
    assert "queue_groups.queue_cursor_id < ?" not in summary[0]
    assert rows[1][-2:] == (99, 51) and summary[1] == ("UTC", [7])
    assert "sum(occurrence_count)" in summary[0]


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize("missing_actor", [False, True])
def test_postgres_groups_209_findings_and_pages_all_61_rows(missing_actor):
    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN is not configured")
    import psycopg
    from psycopg.rows import dict_row

    from server.sli.core.database import _pg_sql
    from tests.postgres_integration_guard import assert_disposable_database

    # Complete retained witnesses keep their cohorts even without a saved actor.
    fixtures = """with findings_active as (
        select n::bigint as id,'synthetic-rule'::text as rule_code,'new'::text as status,
            'high'::text as severity,1::bigint as evidence_count,
            'S-1-5-21-1-' || case when n<=149 then '1101' else n::text end as target,
            'synthetic-actor'::text as actor,
            '2026-10-25T12:00:00Z'::text as first_seen_utc,
            '2026-10-25T12:00:00Z'::text as last_seen_utc
        from generate_series(1,209) n
    ), finding_entities as (select null::bigint as finding_id,null::text as display_name,
            'container_entity'::text as entity_role where false),
    finding_evidence as (select id as finding_id,id as event_id from findings_active),
    events_v2_core as (
        select id,4728 as event_id,7 as domain_id,11 as server_id,
            '2026-10-25T12:00:00Z'::timestamptz as time_created_utc,
            'S-1-5-21-1-512'::text as target_user_sid,1 as channel_id,1 as provider_id
        from findings_active
    ), event_facts_v2 as (
        select id as event_id,'S-1-5-21-1-' || case when id<=149 then '1101' else id::text end as membership_member_sid
        from findings_active
    ), storage_v2_channel(id,value) as (values(1,'Security')),
    storage_v2_provider(id,value) as (values(1,'Microsoft-Windows-Security-Auditing')),
    domains(id,fqdn) as (values(7,'example.invalid')),"""
    if missing_actor:
        fixtures = fixtures.replace("'synthetic-actor'::text", "null::text")
    cte = queue_cohorts_cte("from findings_active findings", "", "findings.status", "false",
        cohort_join=QUEUE_COHORT_JOIN)
    cte = fixtures + cte.removeprefix("with ")
    with psycopg.connect(dsn, row_factory=dict_row) as conn, conn.transaction(force_rollback=True):
        assert_disposable_database(conn)
        count = conn.execute(_pg_sql(cte + "select count(*) as groups,sum(occurrence_count) as occurrences from queue_groups"), ("UTC",)).fetchone()
        assert count == {"groups": 61, "occurrences": 209}
        loaded, after = [], None
        for _ in range(2):
            where = " where queue_cursor_id < ?" if after is not None else ""
            params = ("UTC", after, 51) if after is not None else ("UTC", 51)
            page = conn.execute(_pg_sql(cte + "select * from queue_groups" + where + " order by queue_cursor_id desc limit ?"), params).fetchall()
            loaded.extend(page[:50])
            after = page[49]["queue_cursor_id"] if len(page)>50 else None
        assert len(loaded) == len({row["id"] for row in loaded}) == 61
        assert sum(row["occurrence_count"] for row in loaded) == 209
        main = next(row for row in loaded if row["occurrence_count"] == 149)
        assert json.loads(json.dumps(main["problem_cohort"]))[0] == "membership"
        assert after is None


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_161_same_findings_group_without_legacy_evidence_and_drill_down_exactly():
    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN is not configured")
    import psycopg
    from psycopg.rows import dict_row

    from server.sli.core.database import _pg_sql
    from server.sli.semantic.problem_groups import QUEUE_COHORT_JOIN, cohort_value
    from tests.postgres_integration_guard import assert_disposable_database

    fixtures = """with findings_active as (
        select n::bigint as id,'synthetic-rule'::text as rule_code,'new'::text as status,
            'high'::text as severity,1::bigint as evidence_count,
            case when n=162 then 'other-actor' when n=164 then null else 'EXAMPLE\\operator' end as actor,
            case when n=163 then 'other-object' else 'synthetic-object' end as target,
            case when n=165 then '2026-10-10T09:14:00Z' else '2026-10-09T09:14:00Z' end as first_seen_utc,
            case when n=165 then '2026-10-10T09:14:00Z' else '2026-10-09T09:14:00Z' end as last_seen_utc
        from generate_series(1,166) n
    ), finding_entities as (select 166::bigint as finding_id,'other-group'::text as display_name,
        'container_entity'::text as entity_role),
    finding_evidence as (select null::bigint as finding_id,null::bigint as event_id where false),
    events_v2_core as (select null::bigint as id,null::integer as event_id,
        null::bigint as domain_id,null::bigint as server_id,null::timestamptz as time_created_utc,
        null::text as target_user_sid,null::integer as channel_id,null::integer as provider_id where false),
    event_facts_v2 as (select null::bigint as event_id,null::text as membership_member_sid where false),
    storage_v2_channel as (select null::integer as id,null::text as value where false),
    storage_v2_provider as (select null::integer as id,null::text as value where false),
    domains as (select null::bigint as id,null::text as fqdn where false), """
    cte = queue_cohorts_cte("from findings_active findings", "", "findings.status", "false",
        cohort_join=QUEUE_COHORT_JOIN)
    with psycopg.connect(dsn, row_factory=dict_row) as conn, conn.transaction(force_rollback=True):
        assert_disposable_database(conn)
        rows = conn.execute(_pg_sql(fixtures + cte.removeprefix("with ") +
            "select * from queue_groups order by occurrence_count desc"), ("UTC",)).fetchall()
        assert [row["occurrence_count"] for row in rows] == [161, 1, 1, 1, 1, 1]
        key = cohort_value(json.dumps(rows[0]["problem_cohort"]))
        members = conn.execute(_pg_sql(fixtures.rstrip(", ") +
            " select findings.id from findings_active findings" + QUEUE_COHORT_JOIN +
            " where cohort.key=?::jsonb order by findings.id"), ("UTC", key)).fetchall()
        assert [row["id"] for row in members] == list(range(1, 162))


@pytest.mark.postgres_integration
@pytest.mark.postgres_historical(371, "password_domain_auto")
def test_queue_grouping_compiles_with_the_migrated_runtime_reader_role():
    """Compile the legacy queue grouping under its real reader role."""
    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("Disposable migrated PostgreSQL required")
    import psycopg

    from server.sli.core.database import _pg_sql
    from tests.postgres_integration_guard import assert_disposable_database

    cte = queue_cohorts_cte("from findings_active findings", " where false", "findings.status", "false",
        cohort_join=QUEUE_COHORT_JOIN)
    with psycopg.connect(dsn) as conn, conn.transaction(force_rollback=True):
        assert_disposable_database(conn)
        conn.execute("set local role adlog_user")
        conn.execute("set local search_path=pg_catalog,public")
        conn.execute("set local statement_timeout='3s'")
        assert conn.execute(_pg_sql(cte + "select * from queue_groups"), ("UTC",)).fetchall() == []
