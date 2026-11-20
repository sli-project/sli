"""Exact home cohorts retain the authorized queue population and drilldown."""
import json
from unittest.mock import Mock

import pytest

from server.sli.semantic import findings
from server.sli.reporting.v2.reports import security_problems as report

COHORT = ["membership", "synthetic-rule", 7, 11, "S-1-5-21-1-1101", "S-1-5-21-1-512", "2026-10-01"]


def test_cohort_value_is_exact_not_an_unvalidated_or_lossy_hash():
    from server.sli.semantic.problem_groups import cohort_value
    value = json.dumps(COHORT)
    assert json.loads(cohort_value(value)) == COHORT
    for invalid in ("{}", '["finding",0]', '["membership","r",7,11,"SID","SID","bad"]',
                    json.dumps([*COHORT[:-1], "2026-02-30"]), json.dumps(["object", "r", True, 11, "x", "2026-10-01"])):
        with pytest.raises(ValueError, match="problem_cohort_invalid"):
            cohort_value(invalid)


def test_queue_cohort_round_trip_and_drilldown_use_published_identities(monkeypatch):
    from server.sli.semantic.problem_groups import cohort_value

    key = ["queue", "synthetic-rule", "synthetic-actor", "synthetic-object", ["synthetic-group"], "2026-10-09"]
    assert json.loads(cohort_value(json.dumps(key))) == key
    for invalid in ([*key[:2], None, *key[3:]], [*key[:4], [None], key[5]], [*key[:5], "invalid"]):
        with pytest.raises(ValueError, match="problem_cohort_invalid"):
            cohort_value(json.dumps(invalid))
    calls = []
    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(findings, "resolve_storage_route", lambda **_: {"route": "v2"})
    monkeypatch.setattr(findings, "get_findings_refresh_status", lambda **_: {})
    monkeypatch.setattr(findings, "query_rows", lambda sql, params=(): calls.append((sql, params)) or [])
    findings.get_security_problems_data(cohort=json.dumps(key), compact=True, domain_ids=[7])
    for sql, params in calls[:2]:
        assert "when retained_cohort.key->>0 <> 'finding' then retained_cohort.key" in sql
        assert "findings.actor,findings.target" in sql and "cohort.key = ?::jsonb" in sql
        assert "semantic_finding_in_domains_v265(findings.id,?::bigint[])" in sql
        assert params[:3] == ("UTC", [7], cohort_value(json.dumps(key)))


def test_singleton_drilldown_keeps_exact_id_even_if_legacy_witness_can_group(monkeypatch):
    calls = []
    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(findings, "resolve_storage_route", lambda **_: {"route": "v2"})
    monkeypatch.setattr(findings, "get_findings_refresh_status", lambda **_: {})
    monkeypatch.setattr(findings, "query_rows", lambda sql, params=(): calls.append((sql, params)) or [])
    findings.get_security_problems_data(cohort='["finding",7]', compact=True, domain_ids=[11])
    for sql, params in calls[:2]:
        assert "findings.id = ?" in sql and "cross join" not in sql
        assert "semantic_finding_in_domains_v265(findings.id,?::bigint[])" in sql
        assert params[:2] == ([11], 7)


def test_cohort_sql_groups_complete_witnesses_before_eight_row_limit(monkeypatch):
    query = Mock(return_value=[])
    monkeypatch.setattr(findings, "query_rows", query)
    findings._home_groups("from findings_active findings", " where findings.id > ?", [7], None, time_zone="Europe/Berlin")
    sql, params = query.call_args.args
    assert params == ("Europe/Berlin", 7, None, None)
    assert "witness.retained_count=findings.evidence_count" in sql
    assert "witness.membership_count=0" in sql  # ambiguous membership cannot use generic object fallback
    assert "count(distinct (e.domain_id,e.server_id" in sql
    assert "group by cohort" in sql
    assert "sum(total) over()" in sql and "count(*) over() as total_groups" in sql
    assert sql.index("count(*) as total") < sql.index("limit 8")
    assert "limit 1" in sql  # bounded representative, not an array of all finding IDs


def test_cohort_filter_and_keyset_do_not_limit_summary_or_lose_scope(monkeypatch):
    calls = []
    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(findings, "resolve_storage_route", lambda **_: {"route": "v2"})
    monkeypatch.setattr(findings, "get_findings_refresh_status", lambda **_: {})
    monkeypatch.setattr(findings, "query_rows", lambda sql, params=(): calls.append((sql, params)) or [])
    raw = findings.get_security_problems_data(cohort=json.dumps(COHORT), cohort_timezone="UTC",
        after_id=99, compact=True, domain_ids=[7], attention_only=True)
    row_sql, row_params = calls[0]
    summary_sql, summary_params = calls[1]
    for sql in (row_sql, summary_sql):
        assert "is_semantic_finding_published_v1(findings.id)" in sql
        assert "semantic_finding_in_domains_v265(findings.id,?::bigint[])" in sql
        assert "cohort.key = ?::jsonb" in sql
        assert "not semantic_finding_suppressed" in sql
    assert "findings.id < ?" in row_sql and "findings.id < ?" not in summary_sql
    assert "order by findings.id desc" in row_sql
    assert row_params[-2:] == (99, 51) and 99 not in summary_params
    assert raw["has_more"] is False


def test_cohort_parameter_is_identity_gated_and_hidden():
    param = next(p for p in report.REPORT.params if p.key == "cohort")
    assert param.hidden and param.field_categories == frozenset({"identity_basic"})


@pytest.mark.postgres_integration
@pytest.mark.postgres_historical(371, "password_domain_auto")
def test_native_cohorts_preserve_188_findings_exact_links_days_and_incomplete_sources():
    """Run legacy cohorts on the final schema that retains their event tables."""
    import os
    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN is not configured")
    import psycopg
    from psycopg.rows import dict_row
    from server.sli.core.database import _pg_sql
    from server.sli.semantic.problem_groups import COHORT_JOIN, home_cohorts, cohort_page
    from tests.postgres_integration_guard import assert_disposable_database

    member, group = COHORT[4:6]
    records, evidence, events, facts = [], [], [], []
    for number in range(1, 211):
        at = "2026-10-02T00:30:00Z" if number == 190 else "2026-10-01T23:30:00Z"
        target = member if number <= 188 or number == 190 else member + "-" + str(number)
        records.append({"id": number, "rule_code": "synthetic-rule", "title": "Synthetic membership",
            # Keep the large cohort intentionally visible among >8 groups.
            "severity": "critical" if number <= 188 else "high",
            "created_at": at, "last_seen_utc": at, "assigned_to": None,
            "actor": None, "target": target, "evidence_count": 2 if number == 193 else 1})
        if number == 197:  # Missing witness cannot be grouped with a guessed object.
            continue
        evidence.append({"finding_id": number, "event_id": number})
        events.append({"id": number, "event_id": 4728, "domain_id": 8 if number == 191 else 7,
            "server_id": 12 if number == 192 else 11, "time_created_utc": at,
            "target_user_sid": group + "-9" if number == 189 else group,
            "channel_id": 2 if number == 194 else 1,
            "provider_id": None if number == 196 else 2 if number == 195 else 1})
        facts.append({"event_id": number, "membership_member_sid": target})
    # Mixed-domain singleton must not be labelled with min(domain) as if known.
    records[197]["evidence_count"] = 2
    evidence.append({"finding_id": 198, "event_id": 1001})
    events.append({**next(item for item in events if item["id"] == 198), "id": 1001, "domain_id": 8})
    facts.append({"event_id": 1001, "membership_member_sid": records[197]["target"]})
    # Valid target length, but JSON quoting exceeds the URL/parameter budget.
    records[209]["target"] = '"' * 2048
    next(item for item in events if item["id"] == 210)["event_id"] = 4624
    fixture_sql = """
        findings_active as (select * from jsonb_to_recordset(?::jsonb) as x(
            id bigint,rule_code text,title text,severity text,created_at timestamptz,last_seen_utc text,
            assigned_to text,actor text,target text,evidence_count bigint)),
        finding_evidence as (select * from jsonb_to_recordset(?::jsonb) as x(finding_id bigint,event_id bigint)),
        events_v2_core as (select * from jsonb_to_recordset(?::jsonb) as x(
            id bigint,event_id integer,domain_id bigint,server_id bigint,time_created_utc timestamptz,
            target_user_sid text,channel_id integer,provider_id integer)),
        event_facts_v2 as (select * from jsonb_to_recordset(?::jsonb) as x(event_id bigint,membership_member_sid text)),
        storage_v2_channel(id,value) as (values(1,'Security'),(2,'Application')),
        storage_v2_provider(id,value) as (values(1,'Microsoft-Windows-Security-Auditing'),(2,'Synthetic-Other-Provider')),
        domains(id,fqdn) as (values(7,'example.invalid'),(8,'other.example.invalid'))
    """
    fixture_params = tuple(json.dumps(value) for value in (records, evidence, events, facts))
    with psycopg.connect(dsn, row_factory=dict_row) as conn, conn.transaction(force_rollback=True):
        assert_disposable_database(conn)
        conn.execute("set local role adlog_user")
        real_query = lambda sql, params: conn.execute(_pg_sql(sql), params).fetchall()
        # No schema shadows here: fail if real columns or reader permissions are wrong.
        assert home_cohorts(real_query, "from findings_active findings", " where false", [], None, "UTC") == []

        def query(sql, params):
            sql = sql.replace("with population as", "with " + fixture_sql + ", population as")
            return conn.execute(_pg_sql(sql), (*fixture_params, *params)).fetchall()
        groups = home_cohorts(query, "from findings_active findings", "", [], None, "UTC")
        assert len(groups) == 8 and all(row["total_problems"] == 210 for row in groups)
        main = next(row for row in groups if row["total"] == 188)
        assert main["cohort"] == COHORT
        assert main["total_groups"] > 8
        # The very same production join/filter retrieves every original finding ID.
        sql = "with " + fixture_sql + " select findings.id from findings_active findings " + COHORT_JOIN
        sql += " where cohort.key=?::jsonb order by findings.id"
        linked = conn.execute(_pg_sql(sql), (*fixture_params, "UTC", json.dumps(main["cohort"]))).fetchall()
        assert [row["id"] for row in linked] == list(range(1, 189))
        berlin = home_cohorts(query, "from findings_active findings", "", [], None, "Europe/Berlin")
        assert any(row["total"] == 189 and row["day"] == "2026-10-02" for row in berlin)
        sql = "with " + fixture_sql + " select findings.id,cohort.key from findings_active findings " + COHORT_JOIN
        sql += " where findings.id between 193 and 197 order by findings.id"
        uncertain = conn.execute(_pg_sql(sql), (*fixture_params, "UTC")).fetchall()
        assert [row["key"] for row in uncertain] == [["finding", value] for value in range(193, 198)]
        singletons = home_cohorts(query, "from findings_active findings",
                                  " where findings.id in (193,198)", [], None, "UTC")
        assert {tuple(row["cohort"]): row["domain_name"] for row in singletons} == {
            ("finding", 193): None, ("finding", 198): None}

        oversized = conn.execute(_pg_sql(sql.replace("findings.id between 193 and 197", "findings.id=210")),
                                 (*fixture_params, "UTC")).fetchone()
        assert oversized["key"] == ["finding", 210]

        # Grow the same exact cohort past the production 200-row bound.
        for number in range(211, 228):
            records.append({**records[0], "id": number})
            evidence.append({"finding_id": number, "event_id": number})
            events.append({**events[0], "id": number})
            facts.append({"event_id": number, "membership_member_sid": member})
        fixture_params = tuple(json.dumps(value) for value in (records, evidence, events, facts))
        enlarged = home_cohorts(query, "from findings_active findings", "", [], None, "UTC")
        assert any(row["total"] == 205 and row["total_problems"] == 227 for row in enlarged)
        # Execute production cohort identity + keyset predicate on actual PG.
        ids, sizes, after_id = [], [], None
        while True:
            where, params = " where cohort.key=?::jsonb", ["UTC", json.dumps(COHORT)]
            if after_id is not None:
                where, params = cohort_page(where, params, after_id)
            page_sql = ("with " + fixture_sql + " select findings.id from findings_active findings "
                        + COHORT_JOIN + where + " order by findings.id desc limit ?")
            raw_page = conn.execute(_pg_sql(page_sql), (*fixture_params, *params, 201)).fetchall()
            page = raw_page[:200]
            ids.extend(row["id"] for row in page)
            sizes.append(len(page))
            if len(raw_page) <= 200:
                break
            after_id = page[-1]["id"]
        assert sizes == [200, 5]
        assert ids == sorted([*range(1, 189), *range(211, 228)], reverse=True)
        assert len(set(ids)) == 205



def test_home_optional_identity_failure_preserves_counts_and_raw_objects(monkeypatch):
    raw = {"cohort": COHORT, "rule_code": "synthetic-rule", "total": 188, "total_problems": 208,
           "object_names": [COHORT[4], COHORT[5]], "domain_name": "example.invalid",
           "representative": {"id": 7, "evidence_count": 1, "target": COHORT[4]}}
    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(findings, "resolve_storage_route", lambda **_: {"route": "v2"})
    monkeypatch.setattr(findings, "get_findings_refresh_status", lambda **_: {})
    monkeypatch.setattr(findings, "query_rows", lambda sql, params=(): [raw] if "with population" in sql else [])
    monkeypatch.setattr(findings, "_attach_postgres_finding_details", Mock(side_effect=RuntimeError("private-source-error")))
    data = findings.get_security_problems_data(home_groups=True, home_group_timezone="UTC", compact=True)
    group = data["decision_groups"][0]
    assert group["total"] == 188 and group["total_problems"] == 208
    assert [item["identifier"] for item in group["objects"]] == COHORT[4:6]
    assert all(item["name"] == "" and item["name_state"] == "unavailable" for item in group["objects"])
    assert group["identity_state"] == "unavailable"
    assert "private-source-error" not in str(data) and "representative" not in group


def test_real_parameter_parser_accepts_generated_long_object_cohort_link():
    from urllib.parse import parse_qs, urlparse
    from server.sli.semantic.problem_groups import cohort_value
    from server.sli.reporting.home_summary import _href
    from server.sli.reporting.v2.definition import parse_params
    for target in ("x" * 300, "Учётка" * 300):
        cohort = cohort_value(json.dumps(["object", "synthetic", 7, 11, target, "2026-10-01"], ensure_ascii=False))
        link = _href(report.REPORT.key, {"domain": 7, "cohort": cohort, "tz": "UTC"})
        params, _ = parse_params(report.REPORT, parse_qs(urlparse(link).query))
        assert params["cohort"] == cohort


def test_optional_home_names_exhausting_real_deadline_keep_proven_totals(monkeypatch):
    from server.sli.reporting import read_timeout
    clock = [100.0]
    monkeypatch.setattr(read_timeout, "monotonic", lambda: clock[0])
    monkeypatch.setattr(read_timeout, "read_timeout_ms", lambda: 1000)
    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(findings, "resolve_storage_route", lambda **_: {"route": "v2"})
    calls = []
    def query(sql, params=()):
        read_timeout.remaining_read_ms()
        calls.append("aggregate" if "with population" in sql else "heartbeat")
        return [{"cohort": COHORT, "rule_code": "synthetic-rule", "total": 188, "total_problems": 208,
            "object_names": COHORT[4:6], "representative": {"id": 7, "evidence_count": 1}}] if "with population" in sql else []
    def refresh(**_):
        read_timeout.remaining_read_ms()
        calls.append("refresh")
        return {}
    def optional(*_, **__):
        calls.append("names")
        clock[0] += 2
        read_timeout.remaining_read_ms()  # Real QueryTimeoutError from the shared exhausted budget.
    monkeypatch.setattr(findings, "query_rows", query)
    monkeypatch.setattr(findings, "get_findings_refresh_status", refresh)
    monkeypatch.setattr(findings, "_attach_postgres_finding_details", optional)
    with read_timeout.report_read_budget():
        data = findings.get_security_problems_data(home_groups=True, home_group_timezone="UTC", compact=True)
    assert data["decision_groups"][0]["total"] == 188
    assert data["decision_groups"][0]["total_problems"] == 208
    assert data["decision_groups"][0]["identity_state"] == "unavailable"
    assert calls == ["aggregate", "heartbeat", "refresh", "names"]


def test_optional_detailed_labels_exhausting_deadline_run_after_mandatory_reads(monkeypatch):
    from server.sli.reporting import read_timeout
    clock, calls = [100.0], []
    monkeypatch.setattr(read_timeout, "monotonic", lambda: clock[0])
    monkeypatch.setattr(read_timeout, "read_timeout_ms", lambda: 1000)
    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(findings, "resolve_storage_route", lambda **_: {"route": "v2"})
    def query(sql, params=()):
        read_timeout.remaining_read_ms()
        calls.append("rows" if "select findings.*" in sql else "summary" if "group by" in sql else "heartbeat")
        return [{"id": 7}] if "select findings.*" in sql else []
    def refresh(**_):
        read_timeout.remaining_read_ms()
        calls.append("refresh")
        return {}
    def labels(rows):
        calls.append("labels")
        clock[0] += 2
        read_timeout.remaining_read_ms()
    monkeypatch.setattr(findings, "query_rows", query)
    monkeypatch.setattr(findings, "get_findings_refresh_status", refresh)
    monkeypatch.setattr(findings, "_attach_postgres_finding_details", lambda *_args, **kwargs:
                        calls.append("evidence") if kwargs["defer_identity_labels"] else pytest.fail("labels not deferred"))
    monkeypatch.setattr(findings, "_attach_problem_identities", labels)
    with read_timeout.report_read_budget():
        data = findings.get_security_problems_data()
    assert data["items"][0]["id"] == 7
    assert data["items"][0]["identity_context"]["snapshot_state"] == "unavailable"
    assert calls == ["rows", "evidence", "summary", "heartbeat", "refresh", "labels"]



@pytest.mark.parametrize('state', ['no_match', 'ambiguous', 'unverified', 'unavailable'])
def test_home_sid_display_keeps_identifiers_and_exact_cohort(monkeypatch, state):
    raw = {'cohort': COHORT, 'rule_code': 'synthetic-rule', 'total': 2, 'total_problems': 2,
           'object_names': COHORT[4:6], 'domain_name': 'example.invalid',
           'representative': {'id': 7, 'evidence_count': 1, 'target': COHORT[4]}}
    monkeypatch.setattr(findings, 'is_postgres_runtime_db', lambda: True)
    monkeypatch.setattr(findings, 'resolve_storage_route', lambda **_: {'route': 'v2'})
    monkeypatch.setattr(findings, 'get_findings_refresh_status', lambda **_: {})
    monkeypatch.setattr(findings, 'query_rows', lambda sql, params=(): [raw] if 'with population' in sql else [])
    def attach(rows, **_):
        rows[0]['identity_context'] = {'snapshot_state': 'lookup_complete', 'principals': {},
                                      'principal_states': {COHORT[4]: state, COHORT[5]: 'unverified'}}
    monkeypatch.setattr(findings, '_attach_postgres_finding_details', attach)
    group = findings.get_security_problems_data(home_groups=True, home_group_timezone='UTC', compact=True)['decision_groups'][0]
    assert group['cohort'] == COHORT and group['total'] == 2
    assert [obj['identifier'] for obj in group['objects']] == COHORT[4:6]
    assert [obj['name'] for obj in group['objects']] == ['', '']
    assert [obj['name_state'] for obj in group['objects']] == [state, 'unverified']


@pytest.mark.parametrize('value', ['ordinary-name', '00000000-0000-4000-8000-000000000001', 'sid:not-a-principal'])
def test_home_does_not_prettify_untyped_identifiers_or_literal_names(value):
    obj = findings._home_identity_object(value, {'snapshot_state': 'unavailable'}, 'example.test')
    assert obj['name'] == value and obj['identifier'] == value and obj['name_state'] == 'literal'


def test_home_retained_name_and_provenance_win_over_identifier_spelling():
    sid = COHORT[4]
    source = {'label': sid, 'source': 'ad_snapshot', 'source_run_id': 'synthetic-run',
              'observed_at_utc': '2026-08-01T00:00:00+00:00', 'event_db_id': 91}
    obj = findings._home_identity_object(sid, {'principals': {sid: source}}, 'example.test')
    assert obj['name'] == sid and obj['name_state'] == 'named'
    assert obj['source'] == source and obj['identifier'] == sid
