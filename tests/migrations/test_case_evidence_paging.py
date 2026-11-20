from __future__ import annotations

import pytest

from server.sli.semantic import investigation_cases as cases


def test_event_page_uses_bounded_keyset_and_keeps_anchor_outside_page():
    class Cursor:
        def execute(self, sql, params=()):
            self.sql, self.params = sql, params
        def fetchall(self):
            assert 'event_db_id < %s' in self.sql
            assert self.params == (7, 501, 101)
            return [{'event_db_id': n} for n in range(500, 399, -1)]
        def fetchone(self):
            if 'count(*)' in self.sql:
                return {'total': 700}
            assert self.params == (7, 12)
            return {'event_db_id': 12}
    result = cases._event_evidence_page(Cursor(), 7, after=501, anchor=12)
    assert len(result['events']) == 100
    assert result['events_next_cursor'] == 401
    assert result['events_total'] == 700
    assert result['anchor_event']['event_db_id'] == 12


def test_event_page_rejects_invalid_cursor_before_sql():
    for value in (0, -1, True, 'x', 2**63):
        with pytest.raises(cases.InvestigationCaseError, match='cursor'):
            cases._event_evidence_page(None, 7, after=value, anchor=None)


def test_reference_page_filters_before_count_and_cursor():
    class Cursor:
        def execute(self, sql, params=()):
            self.sql, self.params = sql, params
        def fetchall(self):
            if 'distinct source_domain_id' in self.sql:
                return [{'source_domain_id': 3}, {'source_domain_id': 9}]
            assert 'source_domain_id=any(%s)' in self.sql
            assert self.params == (7, [3], 101)
            return [{'evidence_kind': 'vpn_accounting_session', 'source_domain_id': 3,
                     'reference_id': f'row-{n}'} for n in range(101)]
        def fetchone(self):
            assert self.params == (7, [3])
            return {'total': 150}
    result = cases._typed_evidence_page(Cursor(), 7, after=None, allowed=lambda d: d == 3)
    assert result['evidence_refs_total'] == 150
    assert len(result['evidence_refs']) == 100
    assert result['evidence_refs_state'] == 'partially_authorized'
    assert result['evidence_refs_next_cursor']


def test_reference_page_with_no_grant_does_not_expose_count_or_cursor():
    class Cursor:
        def execute(self, sql, params=()):
            assert 'distinct source_domain_id' in sql
        def fetchall(self):
            return [{'source_domain_id': 9}]
    result = cases._typed_evidence_page(Cursor(), 7, after=None, allowed=lambda d: False)
    assert result['evidence_refs_total'] == 0
    assert result['evidence_refs_next_cursor'] is None
    assert result['evidence_refs'] == []


@pytest.mark.parametrize('allowed', [False, True])
def test_page_checks_all_case_resources_in_snapshot_before_read(monkeypatch, allowed):
    calls = []
    groups = [[{'kind': 'server', 'id': n}] for n in range(701)]
    class Cursor:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def execute(self, sql, params=()): calls.append(sql)
        def fetchone(self): return {'id': 7}
        def fetchall(self): return []
    class Connection:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def cursor(self): return Cursor()
    monkeypatch.setattr(cases, 'connect', Connection)
    monkeypatch.setattr(cases, '_resource_groups_for_case_ids', lambda cur, ids, **kw: {7: groups})
    def authorize(received):
        assert received is groups
        calls.append('authorize')
        return allowed
    def case_row(cur, case_id, **kwargs):
        assert calls[-1] == 'authorize'
        assert kwargs == {'include_links': False}
        calls.append('read')
        return {'id': 7}
    monkeypatch.setattr(cases, '_case_row', case_row)
    monkeypatch.setattr(cases, '_event_evidence_page', lambda *args, **kwargs: {'events': []})
    monkeypatch.setattr(cases, '_typed_evidence_page', lambda *args, **kwargs: {'evidence_refs': []})
    if allowed:
        assert cases.get_case_evidence_page(7, case_allowed=authorize, reference_allowed=lambda d: True)['id'] == 7
    else:
        with pytest.raises(cases.InvestigationCaseError) as error:
            cases.get_case_evidence_page(7, case_allowed=authorize, reference_allowed=lambda d: True)
        assert error.value.code == 'not_found'
        assert 'read' not in calls
    assert calls[0] == 'set transaction isolation level repeatable read, read only'
    assert "select set_config('statement_timeout', %s, true)" in calls


def test_page_database_timeout_is_explicit_unavailable(monkeypatch):
    import psycopg
    def unavailable():
        raise psycopg.errors.QueryCanceled('synthetic timeout')
    monkeypatch.setattr(cases, 'connect', unavailable)
    with pytest.raises(cases.InvestigationCaseError) as error:
        cases.get_case_evidence_page(7, case_allowed=lambda groups: True, reference_allowed=lambda d: True)
    assert error.value.code == 'unavailable'


@pytest.mark.parametrize('cursor', ['not-base64', 'e30=', 'W10=', 'x' * 1025])
def test_reference_cursor_invalid_input_never_reaches_database(cursor):
    with pytest.raises(cases.InvestigationCaseError) as error:
        cases._typed_evidence_page(None, 7, after=cursor, allowed=lambda d: True)
    assert error.value.code == 'invalid_cursor'


@pytest.fixture
def paging_pg():
    import os

    import psycopg
    from psycopg.rows import dict_row

    from tests.postgres_integration_guard import assert_disposable_database
    dsn = os.environ.get('ADLOG_TEST_PG_DSN')
    if not dsn:
        pytest.skip('Disposable PostgreSQL DSN not configured')
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        assert_disposable_database(conn)
        with conn.cursor() as cur:
            cur.execute('create temporary table investigation_events (investigation_id bigint, event_db_id bigint, relation_status text, added_by text, added_at timestamptz, primary key(investigation_id,event_db_id))')
            cur.execute('create temporary table investigation_evidence_refs (investigation_id bigint,evidence_kind text,source_domain_id bigint,reference_id text,relation_status text,added_by text,added_at timestamptz)')
            cur.execute("insert into investigation_events select 7,n,'confirmed','synthetic','2026-01-01T00:00:00Z'::timestamptz from generate_series(1,701) n")
            cur.execute("insert into investigation_evidence_refs select 7,'vpn_accounting_session',case when n % 2=0 then 3 else 9 end,'radius-session-row:' || lpad(n::text,64,'0'),'confirmed','synthetic','2026-01-01T00:00:00Z'::timestamptz from generate_series(1,1002) n")
            yield cur


@pytest.mark.postgres_integration
def test_pg_all_701_events_page_without_loss_or_duplicates(paging_pg):
    found, cursor = [], None
    while True:
        page = cases._event_evidence_page(paging_pg, 7, after=cursor, anchor=None)
        assert page['events_total'] == 701
        assert len(page['events']) <= 100
        found.extend(row['event_db_id'] for row in page['events'])
        cursor = page['events_next_cursor']
        if cursor is None: break
    assert found == list(range(701, 0, -1))


@pytest.mark.postgres_integration
def test_pg_anchor_beyond_500_is_exact_and_not_foreign(paging_pg):
    result = cases._event_evidence_page(paging_pg, 7, after=None, anchor=1)
    assert result['anchor_event']['event_db_id'] == 1
    assert 1 not in [row['event_db_id'] for row in result['events']]
    assert cases._event_evidence_page(paging_pg, 8, after=None, anchor=1)['anchor_event'] is None


@pytest.mark.postgres_integration
def test_pg_visible_references_page_beyond_500_without_hidden_count(paging_pg):
    found, cursor = [], None
    while True:
        page = cases._typed_evidence_page(paging_pg, 7, after=cursor, allowed=lambda d: d == 3)
        assert page['evidence_refs_total'] == 501
        assert page['evidence_refs_state'] == 'partially_authorized'
        assert all(row['source_domain_id'] == 3 for row in page['evidence_refs'])
        found.extend(row['reference_id'] for row in page['evidence_refs'])
        cursor = page['evidence_refs_next_cursor']
        if cursor is None: break
    assert len(found) == len(set(found)) == 501


@pytest.mark.postgres_integration
def test_pg_denied_references_expose_no_count_or_cursor(paging_pg):
    page = cases._typed_evidence_page(paging_pg, 7, after=None, allowed=lambda d: False)
    assert page == {'evidence_refs': [], 'evidence_refs_total': 0, 'evidence_refs_next_cursor': None, 'evidence_refs_state': 'partially_authorized'}


@pytest.mark.postgres_integration
def test_pg_newer_insert_does_not_shift_event_keyset(paging_pg):
    page = cases._event_evidence_page(paging_pg, 7, after=None, anchor=None)
    paging_pg.execute("insert into investigation_events values (7,702,'confirmed','synthetic',now())")
    next_page = cases._event_evidence_page(paging_pg, 7, after=page['events_next_cursor'], anchor=None)
    assert [row['event_db_id'] for row in next_page['events']] == list(range(601,501,-1))
    assert next_page['events_total'] == 702  # Explicitly not a cross-page snapshot.


@pytest.mark.parametrize('resource_id, expected', [(7, 200), (9, 404)])
def test_paged_route_reuses_exact_case_authorization(monkeypatch, resource_id, expected):
    from http import HTTPStatus

    from server.api.routes import investigations as routes
    access = {
        'capabilities': ['investigations.view'], 'resource_bound_capabilities': [],
        'reports': [{'report_key': 'investigations.workspace', 'allowed': True, 'allowed_actions': ['view'],
                     'grants': [{'scope': {'kind': 'server', 'ids': [7]}, 'allowed_actions': ['view'], 'field_categories': ['security']}]}],
    }
    class Handler:
        def _access_decision(self): return access
        def _send_json(self, payload, status=HTTPStatus.OK): self.sent = payload, status
    handler = Handler()
    def read(case_id, **kwargs):
        assert case_id == '42'
        assert kwargs['event_after'] == '501'
        assert kwargs['anchor_event_id'] == '1'
        if not kwargs['case_allowed']([[{'kind': 'server', 'id': resource_id}]]):
            raise cases.InvestigationCaseError('not_found', 'Investigation was not found')
        return {'id': 42, 'title': 'Synthetic', 'status': 'new', 'created_by': 'synthetic',
                'created_at': '2026-01-01T00:00:00Z', 'updated_at': '2026-01-01T00:00:00Z',
                'events_total': 701, 'events_next_cursor': 401, 'evidence_page_size': 100,
                'evidence_refs_state': 'partially_authorized', 'evidence_refs_total': 0}
    monkeypatch.setattr(routes, 'get_case_evidence_page', read)
    routes.try_handle_get(handler, '/api/v1/investigations/42', {'evidence_page': ['1'], 'event_after': ['501'], 'anchor_event_id': ['1']})
    payload, status = handler.sent
    assert status == expected
    if expected == 200:
        assert payload['events_total'] == 701
        assert payload['evidence_refs_state'] == 'partially_authorized'
        assert payload['evidence_refs_total'] == 0
    else:
        assert payload['error'] == 'not_found'
        assert 'events_total' not in payload


def test_paged_route_module_denial_does_not_read(monkeypatch):
    from server.api.routes import investigations as routes
    class Handler:
        def _access_decision(self): return {}
        def _send_json(self, payload, status): self.status = status
    handler = Handler()
    monkeypatch.setattr(routes, 'get_case_evidence_page', lambda *args, **kwargs: pytest.fail('unauthorized read'))
    routes.try_handle_get(handler, '/api/v1/investigations/42', {'evidence_page': ['1']})
    assert handler.status == 403


@pytest.fixture
def paged_route_reader(monkeypatch):
    """Execute the real route and page reader with only storage rows substituted."""
    from http import HTTPStatus

    from server.api.routes import investigations as routes

    audit = [{'id': 5, 'action': 'created', 'actor': 'synthetic', 'payload': {},
              'created_at': '2026-01-01T00:00:00Z'}]
    statements = []
    class Cursor:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def execute(self, sql, params=()):
            self.sql = sql
            statements.append((sql, params))
        def fetchone(self):
            if 'count(*)' in self.sql: return {'total': 0}
            if 'from investigation_events' in self.sql: return None
            return {'id': 7}
        def fetchall(self):
            return audit if 'from investigation_audit' in self.sql else []
    class Connection:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def cursor(self): return Cursor()
    class Handler:
        def _send_json(self, payload, status=HTTPStatus.OK): self.sent = payload, status
    monkeypatch.setattr(cases, 'connect', Connection)
    monkeypatch.setattr(cases, '_resource_groups_for_case_ids', lambda *a, **kw: {7: []})
    monkeypatch.setattr(cases, '_case_row', lambda *a, **kw: {
        'id': 7, 'title': 'Synthetic', 'status': 'new', 'created_by': 'synthetic',
        'created_at': '2026-01-01T00:00:00Z', 'updated_at': '2026-01-01T00:00:00Z',
    })
    monkeypatch.setattr(routes, '_require_investigation_module', lambda *a: True)
    monkeypatch.setattr(routes, '_investigation_access_decision', lambda *a: {'allowed': True})
    def dispatch(**query):
        handler = Handler()
        routes.try_handle_get(handler, '/api/v1/investigations/7', {'evidence_page': ['1'], **{k: [v] for k, v in query.items()}})
        return handler.sent
    return dispatch, statements, audit


def test_paged_response_preserves_populated_bounded_audit(paged_route_reader):
    dispatch, statements, audit = paged_route_reader
    payload, status = dispatch()
    assert status == 200
    assert payload['audit'] == audit
    audit_sql, params = next((sql, params) for sql, params in statements if 'from investigation_audit' in sql)
    assert 'order by created_at desc,id desc limit 200' in audit_sql
    assert params == (7,)


@pytest.mark.parametrize('parameter', ['event_after', 'anchor_event_id'])
@pytest.mark.parametrize('value', ['²', '9' * 4301, '9223372036854775808', '0', '-1', '1.0', '', '١'], ids=['superscript', 'oversized', 'overflow', 'zero', 'negative', 'decimal', 'empty', 'non_ascii'])
def test_paged_route_rejects_invalid_numeric_parameter_as_400(paged_route_reader, parameter, value):
    dispatch, _, _ = paged_route_reader
    payload, status = dispatch(**{parameter: value})
    assert status == 400
    assert payload['error'] == 'invalid_cursor'


@pytest.mark.parametrize('parameter', ['event_after', 'anchor_event_id'])
def test_paged_route_accepts_positive_bigint_maximum(paged_route_reader, parameter):
    dispatch, statements, _ = paged_route_reader
    _, status = dispatch(**{parameter: '9223372036854775807'})
    assert status == 200
    assert any(9223372036854775807 in params for _, params in statements)


@pytest.mark.postgres_integration
def test_pg_complete_reader_preserves_audit_and_authorizes_in_read_snapshot(paging_pg, monkeypatch):
    """Real reader transaction, all SQL and resource resolution; no live source data."""
    from contextlib import contextmanager

    conn = paging_pg.connection
    paging_pg.execute('create temporary table investigations (id bigint primary key, public_id uuid, title text, status text, owner text, created_by text, created_at timestamptz, updated_at timestamptz, closed_at timestamptz)')
    paging_pg.execute("insert into investigations values (7,null,'Synthetic','new',null,'synthetic',now(),now(),null)")
    paging_pg.execute('create temporary table investigation_notes (id bigint, investigation_id bigint, body text, created_by text, created_at timestamptz)')
    paging_pg.execute('create temporary table investigation_audit (id bigint, investigation_id bigint, action text, actor text, payload jsonb, created_at timestamptz)')
    paging_pg.execute("insert into investigation_audit select n,7,'created','synthetic','{}'::jsonb,'2026-01-01T00:00:00Z'::timestamptz from generate_series(1,205) n")
    paging_pg.execute('create temporary table events_v2_core (id bigint, server_id bigint, channel_id bigint)')
    paging_pg.execute('create temporary table servers (id bigint, domain_id bigint)')
    paging_pg.execute('create temporary table storage_v2_channel (id bigint, value text)')
    paging_pg.execute("insert into storage_v2_channel values (1,'Security')")
    paging_pg.execute('insert into servers values (7,3)')
    paging_pg.execute('insert into events_v2_core select n,7,1 from generate_series(1,701) n')
    conn.commit()  # Reader must establish its transaction before any data query.

    @contextmanager
    def fixture_connect():
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    monkeypatch.setattr(cases, 'connect', fixture_connect)
    monkeypatch.setattr(cases, '_event_route', lambda authorization: 'v2')
    authorized = []
    def case_allowed(groups):
        with conn.cursor() as cur:
            cur.execute("select current_setting('transaction_isolation') as isolation, current_setting('transaction_read_only') as read_only")
            settings = cur.fetchone()
        assert settings == {'isolation': 'repeatable read', 'read_only': 'on'}
        authorized.extend(groups)
        return True
    page = cases.get_case_evidence_page(7, case_allowed=case_allowed, reference_allowed=lambda domain: domain == 3, anchor_event_id=1)
    assert len(authorized) == 703  # 701 exact events plus two typed-reference domains.
    assert authorized[0] == [{'kind': 'server', 'id': 7}, {'kind': 'domain', 'id': 3}, {'kind': 'channel', 'value': 'Security'}]
    assert page['events_total'] == 701
    assert len(page['events']) == 100
    assert page['events_next_cursor'] == 602
    assert page['anchor_event']['event_db_id'] == 1
    assert page['evidence_refs_total'] == 501
    assert len(page['evidence_refs']) == 100
    assert page['evidence_refs_state'] == 'partially_authorized'
    assert [row['id'] for row in page['audit']] == list(range(205,5,-1))
