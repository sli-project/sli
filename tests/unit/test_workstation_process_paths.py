"""WR14: historical native process evidence, never a live-process assertion."""
from copy import deepcopy
from datetime import timedelta
import importlib
import json

import pytest

from server.sli.plugins.workstations import projection
from tests.unit.test_workstation_password_failures import PG, native, NOW, STATION
from tests.unit.test_workstation_projection import prepare, run


def module():
    return importlib.import_module('server.sli.plugins.workstations.process_paths')


@pytest.mark.parametrize('path,category', [
    (r'C:\Windows\Temp\fixture.exe', 'temporary'),
    (r'd:\USERS\fixture\AppData\Local\Temp\folder\fixture.exe', 'temporary'),
    (r'C:\Users\Public\fixture.exe', 'public'),
])
def test_known_conventional_locations_require_review_without_signature_claim(path, category):
    assert module().assess_path(path) == {'status': 'matched', 'category': category, 'path': path}


@pytest.mark.parametrize('path', [None, '', '-', r'C:Temp\x.exe', r'\Temp\x.exe',
    r'\\host\share\x.exe', r'\\?\C:\Windows\Temp\x.exe', r'\Device\x.exe',
    r'C:\Windows\Temp\..\x.exe', r'C:\Windows\Temp\.\x.exe',
    r'C:\Windows\Temp\x.exe:stream', r'C:\Windows\Temp\x.exe ',
    r'C:/Windows/Temp/x.exe', r'%TEMP%\x.exe', 'C:\\Windows\\Temp\\',
    'C:\\Windows\\Temp\\x\x00.exe', 'C:\\Windows\\Temp\\' + 'x' * 2048,
    r'C:\Windows\Temp\NUL.exe', r'C:\Windows\Temp\\x.exe',
])
def test_ambiguous_missing_or_bounded_paths_are_not_assessed(path):
    assert module().assess_path(path) == {'status': 'not_assessed', 'category': None, 'path': None}


@pytest.mark.parametrize('path', [r'C:\Windows\System32\fixture.exe', r'C:\Windows\Temporary\x.exe',
    r'C:\Users\Publicity\x.exe', r'C:\Users\fixture\AppData\Local\Tempest\x.exe'])
def test_other_absolute_paths_are_not_a_safety_verdict(path):
    assert module().assess_path(path)['status'] == 'no_match'


def test_native_normalizer_queue_publication_and_replay_preserve_historical_identity():
    c04 = module()
    row = native(number=4688, NewProcessName=r'C:\Windows\Temp\fixture.exe', NewProcessId='0x11')
    assert row['observation']['facts']['process_name'] == r'C:\Windows\Temp\fixture.exe'
    pg = PG(row)
    evaluators = tuple(rule for rule in projection.projectors() if rule.key == c04.PROJECTOR)
    assert len(evaluators) == 1
    prepare(pg, evaluators)
    pg.add_fact(row['id'], payload=json.loads(json.dumps(row, default=str)))
    assert run(pg, evaluators)['processed'] == 1
    finding = next(iter(pg.findings.values()))
    assert finding['check_id'] == 'C04' and finding['severity'] == 'medium'
    assert finding['fact_at'] == row['observed_at'] < finding['first_detected_at'] == NOW
    assert finding['reason_params']['signature_status'] == 'not_received'
    assert finding['subject_ref']['current_state'] == 'unknown'
    assert finding['evidence_refs'][0]['observation_id'] == row['id']
    original = deepcopy(finding)
    pg.now = NOW + timedelta(days=1)
    pg.add_fact(row['id'], payload=json.loads(json.dumps(row, default=str)))
    assert run(pg, evaluators)['processed'] == 0
    assert next(iter(pg.findings.values())) == original


def test_non_process_or_untrusted_native_identity_produces_no_finding():
    c04 = module()
    row = native(number=4688, NewProcessName=r'C:\Users\Public\fixture.exe')
    for field, value in [('family', 'logons'), ('event_id', 4697)]:
        assert c04.finding({**row, field: value}, station_id=STATION, detected_at=NOW) is None
    for field, value in [('channel', 'System'), ('provider_name', 'fixture-untrusted')]:
        changed = deepcopy(row)
        changed['observation'][field] = value
        assert c04.finding(changed, station_id=STATION, detected_at=NOW) is None
    other = deepcopy(row)
    other['observation']['facts']['process_name'] = r'C:\Windows\System32\fixture.exe'
    assert c04.finding(other, station_id=STATION, detected_at=NOW) is None


def test_source_ids_and_station_identity_are_not_merged_by_path_or_pid():
    c04 = module()
    row = native(number=4688, NewProcessName=r'C:\Users\Public\fixture.exe', NewProcessId='0x11')
    other = native(record=2, number=4688, NewProcessName=r'C:\Users\Public\fixture.exe', NewProcessId='0x11')
    first = c04.finding(row, station_id=STATION, detected_at=NOW)
    second = c04.finding(other, station_id=STATION, detected_at=NOW)
    third = c04.finding(row, station_id='fixture-other', detected_at=NOW)
    assert len({first['id'], second['id'], third['id']}) == 3


def test_wrong_agent_is_not_published_and_failure_keeps_receipt_pending():
    c04 = module()
    row = native(number=4688, NewProcessName=r'C:\Users\Public\fixture.exe')
    pg = PG(row)
    evaluators = (projection.Projector(c04.PROJECTOR, c04.RULE_VERSION, c04.apply),)
    prepare(pg, evaluators)
    pg.add_fact(row['id'], payload=json.loads(json.dumps(row, default=str)))
    pg.station_agent = 'fixture-other'
    with pytest.raises(ValueError, match='input_conflict'):
        run(pg, evaluators)
    assert not pg.findings and not next(iter(pg.receipts.values()))['applied']
    pg.station_agent = row['agent_key']
    pg.fail_save = True
    with pytest.raises(RuntimeError, match='publication failure'):
        run(pg, evaluators)
    assert not pg.findings and not next(iter(pg.receipts.values()))['applied']
    pg.fail_save = False
    assert run(pg, evaluators)['processed'] == 1


def test_multibyte_bounds_and_unknown_paths_never_create_false_findings():
    c04 = module()
    path = 'C:\\Users\\Public\\' + 'я' * 260 + '.exe'
    assert c04.assess_path(path)['status'] == 'not_assessed'
    row = native(number=4688, NewProcessName=path)
    assert row['observation']['facts'].get('process_name') is None
    assert c04.finding(row, station_id=STATION, detected_at=NOW) is None


def test_signature_copy_exists_on_server_and_frontend_in_both_languages():
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    key = 'workstations.process.signature_not_received'
    for locale in ('ru', 'en'):
        messages = json.loads((root / f'config/i18n/server.{locale}.json').read_text())
        assert messages.get(key)
        assert f'"{key}":' in (root / f'frontend/src/i18n/{locale}.ts').read_text()


@pytest.mark.parametrize('field,value', [('id', '42'), ('agent_key', ''), ('source_sha256', 'not-a-hash')])
def test_invalid_source_identity_cannot_become_evidence(field, value):
    row = native(number=4688, NewProcessName=r'C:\Users\Public\fixture.exe')
    if field == 'source_sha256':
        row['observation'][field] = value
    else:
        row[field] = value
    with pytest.raises(ValueError, match='source_invalid'):
        module().finding(row, station_id=STATION, detected_at=NOW)
