"""Synthetic existing importer/finding pipeline; no live data or native trust calls."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from server.sli.plugins.workstations import importer, overview, process_paths
from sli_collect.eventlog import event_packet, parse_event_xml
from tests.unit.test_workstation_signature_contract import NOW, native_packet
from tests.unit.test_workstations_plugin import STATION, Cursor, connection


def fixture():
    capsule, sources = native_packet()
    row = parse_event_xml(sources[0]['xml'], source_name='fixture', connect_address='', channel='Security')
    packet = event_packet(row, generation='fixture-generation', after_record_id=11)
    packet['header']['observed_at_utc'] = NOW.isoformat()
    packet['context'] = capsule['context']
    return packet, [row]


def project(cur, packet, rows):
    return importer.project_packet(connection(cur), packet, rows, agent_key=STATION.agent_key,
        identity=SimpleNamespace(workstation=lambda conn, key: STATION))


def test_import_preserves_original_measurement_on_replay_and_card_is_not_process_trust():
    cur = Cursor(); packet, rows = fixture()
    assert project(cur, packet, rows)['inserted'] == 1
    saved = deepcopy(next(iter(cur.stored.values())))
    observation = saved['observation']
    assert observation['file_signature'] == packet['context']['workstations']['process_signatures'][0]
    packet['context']['workstations']['process_signatures'][0]['measurement']['signer_sha256'] = 'd'*64
    assert project(cur, packet, rows)['inserted'] == 0
    assert next(iter(cur.stored.values())) == saved
    row = {'id': 'e'*64, 'agent_key': STATION.agent_key, 'family': 'processes', 'event_id': 4688,
               'observation': observation, 'observed_at': NOW}
    result = process_paths.finding(row, station_id='station', detected_at=NOW)
    assert result['severity'] == 'medium'
    assert result['subject_ref']['current_state'] == 'unknown'
    card = overview.finding_card(result, 'station')['process_details']
    assert card['current_state'] == 'unknown'
    assert card['file_measurement']['scope'] == 'file_at_measurement'
    assert card['file_measurement']['sha256_before'] == 'a'*64


def test_bad_measurement_rejected_before_any_database_write():
    cur = Cursor(); packet, rows = fixture()
    packet['context']['workstations']['process_signatures'][0]['measurement']['sha256_after'] = 'b'*64
    with pytest.raises(ValueError):
        project(cur, packet, rows)
    assert not cur.calls


def test_assigned_ingest_validates_extension_after_existing_policy_admission():
    import hashlib
    from uuid import uuid4

    from cryptography.hazmat.primitives.asymmetric import ec

    from server.sli.agents.workstation_ingest import workstation_rows
    from sli_agent.envelope import make_packet
    from sli_agent.workstations import WorkstationsModule
    from tests.unit.test_workstation_signature_contract import entry

    host, agent = str(uuid4()), str(uuid4())
    native = native_packet()[1][0]['xml']
    collector = WorkstationsModule(host, {}, reader=lambda *_: [(native, 'bookmark-12')])
    sample = collector.collect(None, now=NOW)
    capsule = entry()
    capsule['source_sha256'] = hashlib.sha256(native.encode()).hexdigest()
    capsule['measurement']['observed_at_utc'] = NOW.isoformat()
    sample.payload['context']['workstations']['process_signatures'] = [capsule]
    packet = make_packet(ec.generate_private_key(ec.SECP256R1()), agent_id=agent,
                         sequence=1, sample=sample, now=NOW)
    identity = {'host_id': host, 'assigned_modules': [{'module_id': 'sli.workstations', 'enabled': True, 'config': {}}]}
    assert len(workstation_rows(identity, packet['envelope'], packet['payload'])) == 1
    packet['payload']['context']['workstations']['process_signatures'][0]['path'] = r'C:\wrong.exe'
    with pytest.raises(ValueError, match='signature_binding'):
        workstation_rows(identity, packet['envelope'], packet['payload'])


@pytest.mark.parametrize('suffix', ['\u00a0', '\u2007', '\u202f'])
def test_native_path_trim_ambiguity_rejects_capsule_before_writes_but_keeps_legacy_event(suffix):
    import hashlib

    from tests.unit.test_workstation_signature_contract import PATH

    packet, rows = fixture()
    xml = rows[0]['xml'].replace(PATH, PATH + suffix)
    rows = [parse_event_xml(xml, source_name='fixture', connect_address='', channel='Security')]
    packet = {**packet, **event_packet(rows[0], generation='fixture-generation', after_record_id=11),
              'context': packet['context']}
    packet['header']['observed_at_utc'] = NOW.isoformat()
    capsule = packet['context']['workstations']['process_signatures'][0]
    capsule['path'] = PATH + suffix
    capsule['source_sha256'] = hashlib.sha256(xml.encode()).hexdigest()
    rejected = Cursor()
    with pytest.raises(ValueError, match='signature_binding'):
        project(rejected, packet, rows)
    assert not rejected.calls

    # The event remains admissible without optional ambiguous measurement data.
    packet['context']['workstations'].pop('process_signatures')
    cur = Cursor()
    assert project(cur, packet, rows)['inserted'] == 1
    observation = next(iter(cur.stored.values()))['observation']
    assert observation['facts']['process_name'] == PATH
    finding = process_paths.finding({'id': 'e'*64, 'agent_key': STATION.agent_key,
        'family': 'processes', 'event_id': 4688, 'observation': observation, 'observed_at': NOW},
        station_id='station', detected_at=NOW)
    assert finding['subject_ref']['signature_status'] == 'not_received'
    assert finding['subject_ref']['current_state'] == 'unknown'
