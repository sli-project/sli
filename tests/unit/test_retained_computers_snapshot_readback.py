"""Synthetic connection contexts only: no PostgreSQL server or real writes."""
import json
from datetime import UTC, datetime
from uuid import UUID

import pytest

from scripts.runtime import computers_report_v5_snapshot_worker as v5
from scripts.runtime import computers_report_v6_snapshot_worker as v6


class Connection:
    def __init__(self, defect=None):
        self.defect = defect
        self.statements = []
        self.rowcount = 2
        self.committed = False
        self.rolled_back = False

    def __enter__(self):
        return self

    def __exit__(self, kind, *_):
        self.committed = kind is None
        self.rolled_back = kind is not None

    def cursor(self):
        from contextlib import nullcontext
        return nullcontext(self)

    def execute(self, sql, params=()):
        self.statements.append((sql, params))
        if 'insert into' in sql:
            self.insert_params = params

    def fetchall(self):
        return [{'id': 7}]

    def fetchone(self):
        if 'insert into' in self.statements[-1][0]:
            return None if self.defect == 'conflict' else {'snapshot_id': 19}
        result = {'object_count': self.insert_params[8], 'payload_sha256': self.insert_params[10]}
        if self.defect == 'missing_row':
            return None
        if self.defect == 'missing_count':
            del result['object_count']
        elif self.defect == 'null_count':
            result['object_count'] = None
        elif self.defect == 'wrong_count':
            result['object_count'] += 1
        elif self.defect == 'hash':
            result['payload_sha256'] = b'wrong'
        return result


@pytest.fixture(params=[v5, v6], ids=['v5', 'v6'])
def worker(request, monkeypatch):
    from server.sli.sources import legacy_collection
    monkeypatch.setattr(legacy_collection, 'require_legacy_collection', lambda: None)
    monkeypatch.setattr(request.param, 'report_domain_fqdn', lambda: 'synthetic.example.invalid')
    return request.param


def run(worker, connection, count):
    version = 'v5' if worker is v5 else 'v6'
    report = {
        'state': 'empty' if not count else 'available',
        'contract_id': f'sli.computers-report.{version}',
        'report_key': f'ad.computers.{version}',
        'items': [{'entity_id': i} for i in range(count)],
        'coverage': {'domains': [{'domain_id': 7, 'run_id': '00000000-0000-0000-0000-000000000007'}]},
        'threshold': {'selected_days': 60},
    }
    def loader(**kwargs):
        assert kwargs['domain_ids'] == [7]
        return report
    return worker.run_once(connection_factory=lambda: connection, report_loader=loader,
                           captured_at=datetime(2026, 10, 22, tzinfo=UTC))


@pytest.mark.parametrize('count', [0, 2])
def test_valid_readback_commits_before_retention_result(worker, count):
    connection = Connection()
    result = run(worker, connection, count)
    assert result['status'] == 'captured'
    assert result['object_count'] == count
    assert result['retired_snapshots'] == 2
    assert connection.committed and not connection.rolled_back
    assert 'select object_count' in connection.statements[-2][0]
    assert 'delete from' in connection.statements[-1][0]
    assert connection.insert_params[0] == 7
    assert connection.insert_params[1] == UUID('00000000-0000-0000-0000-000000000007')
    assert json.loads(connection.insert_params[3])['domain_ids'] == [7]


@pytest.mark.parametrize('defect', ['missing_row', 'missing_count', 'null_count', 'wrong_count', 'hash'])
@pytest.mark.parametrize('count', [0, 2])
def test_invalid_readback_rolls_back_and_never_retires(worker, defect, count):
    connection = Connection(defect)
    with pytest.raises(RuntimeError, match='snapshot_readback_mismatch'):
        run(worker, connection, count)
    assert connection.rolled_back and not connection.committed
    assert not any('delete from' in sql for sql, _ in connection.statements)


def test_conflicting_bucket_still_skips_retention(worker):
    connection = Connection('conflict')
    assert run(worker, connection, 0)['status'] == 'already_captured'
    assert not any('delete from' in sql for sql, _ in connection.statements)
