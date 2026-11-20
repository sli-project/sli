"""Closed file-measurement contract, never historical execution trust."""
import hashlib
import importlib
from datetime import UTC, datetime

import pytest

NOW = datetime(2026, 10, 28, 12, tzinfo=UTC)
PATH = r'C:\Windows\Temp\sample.exe'


def row():
    return {'event_id': 4688, 'record_id': 12, 'channel': 'Security',
                'provider_name': 'Microsoft-Windows-Security-Auditing',
                'xml': '<native/>', 'process_path': PATH}


def entry():
    return {'contract': 'sli.workstation-file-signature.v1', 'record_id': 12,
                'source_sha256': hashlib.sha256(b'<native/>').hexdigest(), 'path': PATH,
                'measurement': {'scope': 'file_at_measurement', 'observed_at_utc': NOW.isoformat(),
                                 'status': 'signed', 'reason': None, 'sha256_before': 'a'*64,
                                 'sha256_after': 'a'*64, 'identity_before': 'b'*64, 'identity_after': 'b'*64,
                                 'signer_sha256': 'c'*64, 'kind': 'embedded'}}


def api():
    return importlib.import_module('sli_agent.signature_contract')


def test_valid_measurement_detached_and_not_process_trust():
    value = entry()
    result = api().validate_entries([value], [row()], packet_time=NOW)
    assert result[12] == value
    result[12]['measurement']['status'] = 'changed'
    assert value['measurement']['status'] == 'signed'
    assert 'process_trusted' not in result[12]


@pytest.mark.parametrize('field,value', [('event_id',4624), ('record_id',13), ('channel','System'),
    ('provider_name','other'), ('xml','other'), ('process_path',r'C:\other.exe')])
def test_reject_binding(field, value):
    source = row(); source[field] = value
    with pytest.raises(ValueError):
        api().validate_entries([entry()], [source], packet_time=NOW)


@pytest.mark.parametrize('field,value', [('scope','executed_binary'), ('sha256_after','d'*64),
    ('identity_after','d'*64), ('signer_sha256',None), ('kind','none'), ('status','healthy'),
    ('observed_at_utc','2026-10-28T12:00:06+00:00'), ('observed_at_utc','2026-10-28T11:59:58+00:00'),
    ('observed_at_utc','2026-10-28T12:00:00')])
def test_reject_measurement(field, value):
    source = entry(); source['measurement'][field] = value
    with pytest.raises(ValueError):
        api().validate_entries([source], [row()], packet_time=NOW)


@pytest.mark.parametrize('path', [r'\\server\a.exe',r'\\?\C:\a.exe',r'C:\a.exe:stream',
    r'a.exe',r'C:\a\..\b.exe','C:\\a\x00.exe',r'C:\foo~1\a.exe','C:\\a.exe '])
def test_ambiguous_paths_rejected(path):
    assert api().local_path(path) is None


def test_closed_and_bounded():
    for values in ([entry(), entry()], [entry()]*3):
        with pytest.raises(ValueError):
            api().validate_entries(values, [row()], packet_time=NOW)
    value = entry(); value['process_trusted'] = True
    with pytest.raises(ValueError):
        api().validate_entries([value], [row()], packet_time=NOW)


def test_unsigned_unavailable_and_legacy():
    value = entry(); value['measurement'].update(status='unsigned',kind='none',signer_sha256=None)
    assert api().validate_entries([value], [row()], packet_time=NOW)[12] == value
    value['measurement'] = api().unavailable('timeout', NOW)
    assert api().validate_entries([value], [row()], packet_time=NOW)[12] == value
    for absent in (None, []):
        assert api().validate_entries(absent, [row()], packet_time=NOW) == {}


@pytest.mark.parametrize('field', ['status', 'reason', 'kind', 'observed_at_utc'])
def test_wrong_types_rejected_without_typeerror(field):
    value = entry(); value['measurement'][field] = []
    with pytest.raises(ValueError):
        api().validate_entries([value], [row()], packet_time=NOW)


def native_packet():
    xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
           '<System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID>'
           '<EventRecordID>12</EventRecordID><Channel>Security</Channel>'
           '<TimeCreated SystemTime="2026-10-28T12:00:00Z"/><Computer>fixture</Computer></System>'
           '<EventData><Data Name="NewProcessName">'+PATH+'</Data></EventData></Event>')
    source = row(); source.update(xml=xml, computer_name='fixture')
    value = entry(); value['source_sha256'] = hashlib.sha256(xml.encode()).hexdigest()
    return {'header':{'observed_at_utc':NOW.isoformat()},
            'context':{'workstations':{'process_signatures':[value]}}}, [source]


def test_packet_reads_exact_native_path_not_supplied_row_path():
    packet, rows = native_packet()
    rows[0]['process_path'] = r'C:\wrong.exe'
    assert api().packet_entries(packet, rows)[12]['path'] == PATH
    packet['context']['workstations']['process_signatures'][0]['path'] = r'C:\wrong.exe'
    with pytest.raises(ValueError):
        api().packet_entries(packet, rows)


def test_packet_rejects_duplicate_path_and_native_identity_mismatch():
    packet, rows = native_packet()
    rows[0]['event_id'] = 4624
    with pytest.raises(ValueError):
        api().packet_entries(packet, rows)
    packet, rows = native_packet()
    rows[0]['xml'] = rows[0]['xml'].replace('</EventData>', '<Data Name="NewProcessName">x</Data></EventData>')
    with pytest.raises(ValueError):
        api().packet_entries(packet, rows)
