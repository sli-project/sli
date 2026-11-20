"""Real context reads in the disposable PostgreSQL CI job; no stand access."""
import os
from http import HTTPStatus

import pytest

from tests.postgres_integration_guard import assert_disposable_database


@pytest.mark.postgres_integration
@pytest.mark.parametrize('with_controller,expected', [
    (False, 'domain_controllers_missing'), (True, 'users_context_missing'),
])
def test_report_explains_missing_context_from_real_postgres(monkeypatch, with_controller, expected):
    dsn = os.environ.get('ADLOG_TEST_PG_DSN', '').strip()
    if not dsn:
        pytest.skip('ADLOG_TEST_PG_DSN is required for disposable PostgreSQL integration')
    psycopg = pytest.importorskip('psycopg')
    from psycopg.rows import dict_row
    from server.api.routes import reports_v2
    from server.sli.reporting.v2.reports import computer_logons
    from server.sli.plugins.ad.reports import new_logon_pairs_reporting as engine

    with psycopg.connect(dsn, row_factory=dict_row) as connection:
        assert_disposable_database(connection)
        forest = connection.execute("insert into forests(name) values ('t002.example.test') returning id").fetchone()['id']
        domain = connection.execute(
            "insert into domains(forest_id,fqdn) values (%s,'t002.example.test') returning id", (forest,),
        ).fetchone()['id']
        if with_controller:
            connection.execute("insert into servers(domain_id,hostname,role) values (%s,'dc-t002','domain_controller')", (domain,))
    monkeypatch.setenv('ADLOG_PG_DSN', dsn)
    monkeypatch.setattr(computer_logons, 'resolve_report_domain_id', lambda: domain)
    def no_history(*args):
        pytest.fail('missing context must not start history reads')
    monkeypatch.setattr(engine, 'load_history', no_history)

    class Handler:
        def _access_decision(self):
            return {'reports': [{'report_key': 'ad.computer-logons', 'allowed': True,
                'allowed_actions': ['view'], 'grants': [{'allowed_actions': ['view'],
                'field_categories': ['computer_logon_observation'], 'scope': {'kind': 'domain', 'ids': [domain]}}]}]}
        def _send_json(self, payload, status=HTTPStatus.OK):
            self.payload, self.status = payload, status
    handler = Handler()
    assert reports_v2.try_handle_get(handler, '/api/v2/reports/ad.new-logon-pairs/data', {})
    assert handler.status == HTTPStatus.OK
    assert handler.payload['state'] == 'error' and not handler.payload['items']
    assert handler.payload['limitations'][0]['code'] == expected
