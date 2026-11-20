"""WR14 historical 4688 path candidates, within WR05's publication fence.

Version 1 recognises conventional drive-root Windows\\Temp, Users\\Public and
Users\\<profile>\\AppData\\Local\\Temp locations. This is a lexical review rule,
not proof of actual environment locations, writable ACLs, malware, signature or
current execution. Unknown paths are not assessed; no-match never means safe.
No filesystem, environment expansion, network, process or signature lookup.
"""
from __future__ import annotations

import json
import re

from server.sli.sources.process_identity_contract import (
    bounded_process_text,
    windows_process_id,
)
from sli_agent.signature_contract import CONTRACT, validate_measurement

from .check_catalog import BY_ID
from .importer import digest
from .normalizers import SECURITY_PROVIDER
from .overview_contracts import Quality, Reason
from .protection import timestamp

PROJECTOR = 'workstations.C04'
RULE_VERSION = BY_ID['C04'].rule_version
MAX_PATH_BYTES = 512
_RESERVED = re.compile(r'(?:con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?', re.I)


def assess_path(value):
    """Keep original evidence; compare only unambiguous absolute DOS segments.

    Refuse device/UNC paths, aliases, ADS, dot segments and ambiguous names
    instead of resolving them on this server or guessing the station's layout.
    """
    unknown = {'status': 'not_assessed', 'category': None, 'path': None}
    if not isinstance(value, str):
        return unknown
    try:
        size = len(value.encode('utf-8'))
    except UnicodeEncodeError:
        return unknown
    if not 1 <= size <= MAX_PATH_BYTES or not re.match(r'^[A-Za-z]:\\', value):
        return unknown
    parts = value[3:].split('\\')
    if any(not part or part in ('.', '..') or part.endswith((' ', '.'))
           or _RESERVED.fullmatch(part) or '~' in part
           or any(ord(char) < 32 or ord(char) == 127 or char in '/:"<>|?*%' for char in part)
           for part in parts):
        return unknown
    lower = [part.casefold() for part in parts]
    category = None
    if len(parts) >= 3 and lower[:2] == ['windows', 'temp']:
        category = 'temporary'
    elif len(parts) >= 6 and lower[0] == 'users' and lower[2:5] == ['appdata', 'local', 'temp']:
        category = 'temporary'
    elif len(parts) >= 3 and lower[:2] == ['users', 'public']:
        category = 'public'
    return {'status': 'matched' if category else 'no_match', 'category': category, 'path': value}


def finding(row, *, station_id, detected_at):
    observation = row.get('observation', {})
    if (row.get('family') != 'processes' or row.get('event_id') != 4688
            or str(observation.get('channel', '')).casefold() != 'security'
            or str(observation.get('provider_name', '')).casefold() != SECURITY_PROVIDER.casefold()):
        return None
    facts = observation.get('facts', {})
    # The shared native normalizer emits process_name, not a display fallback.
    assessment = assess_path(facts.get('process_name'))
    if assessment['status'] != 'matched':
        return None
    identifier, agent = row.get('id'), row.get('agent_key')
    source_hash = observation.get('source_sha256')
    if (not isinstance(identifier, str) or not re.fullmatch(r'[a-f0-9]{64}', identifier)
            or not isinstance(agent, str) or not 1 <= len(agent) <= 256
            or (source_hash is not None and (not isinstance(source_hash, str)
                                           or not re.fullmatch(r'[a-f0-9]{64}', source_hash)))):
        raise ValueError('workstation_c04_source_invalid')
    at = timestamp(row['observed_at'])
    detected_at = timestamp(detected_at)
    episode = digest([PROJECTOR, RULE_VERSION, station_id, agent, identifier])
    subject = {'kind': 'workstation_process_observation', 'station_id': station_id,
               'observation_id': identifier, 'path': assessment['path'],
               'process_id': windows_process_id(facts.get('process_id')),
               'current_state': 'unknown', 'signature_status': 'not_received',
               'signature_message_key': 'workstations.process.signature_not_received'}
    capsule = observation.get('file_signature')
    if capsule is not None:
        if (not isinstance(capsule, dict)
                or set(capsule) != {'contract', 'record_id', 'source_sha256', 'path', 'measurement'}
                or capsule['contract'] != CONTRACT or capsule['record_id'] != observation.get('record_id')
                or capsule['source_sha256'] != source_hash or capsule['path'] != assessment['path']):
            raise ValueError('workstation_signature_binding_invalid')
        subject['file_measurement'] = validate_measurement(capsule['measurement'])
        # A measured file is not a verified historical process image.
        subject['signature_status'] = 'unknown'
        subject.pop('signature_message_key', None)
    for field in ('process_user_sid', 'process_user_name', 'process_user_domain'):
        subject[field] = bounded_process_text(facts.get(field), field)
    params = {'path': assessment['path'], 'path_category': assessment['category'],
              'path_policy_version': RULE_VERSION, 'signature_status': subject['signature_status']}
    refs = [{'kind': 'workstation_observation', 'observation_id': identifier,
             'agent_key': agent, 'source_sha256': source_hash}]
    return {'id': episode, 'station_id': station_id, 'check_id': 'C04', 'rule_version': RULE_VERSION,
            'subject_id': identifier, 'subject_ref': subject, 'episode_id': episode,
            'condition_sha256': digest([subject, params, refs]), 'status': 'active',
            'severity': BY_ID['C04'].severity, 'fact_at': at, 'first_detected_at': detected_at,
            'last_observed_at': at, 'materially_changed_at': detected_at,
            'reason_code': BY_ID['C04'].reason_code, 'reason_params': params,
            'quality': Quality('partial', (Reason('coverage_incomplete'),)).to_dict(), 'evidence_refs': refs}


def apply(conn, station_id, fact):
    if fact['kind'] != 'observations':
        return
    row = fact['payload']
    with conn.cursor() as cur:
        cur.execute("set local statement_timeout='5000ms'")
        cur.execute('select transaction_timestamp() as detected_at')
        result = finding(row, station_id=station_id, detected_at=cur.fetchone()['detected_at'])
        if result is None:
            return
        cur.execute('select agent_key from sli_plugin_workstations.station_inventory where station_id=%s', (station_id,))
        station = cur.fetchone()
        if not station or station['agent_key'] != row['agent_key']:
            raise ValueError('workstation_projection_input_conflict')
        values = tuple(json.dumps(value) if isinstance(value, (dict, list)) else value for value in result.values())
        slots = ['%s::jsonb' if isinstance(value, (dict, list)) else '%s' for value in result.values()]
        # One immutable observation/rule version, not one current process/PID.
        # Retry cannot move first_detected_at, create a revision, or duplicate it.
        cur.execute(f"""insert into sli_plugin_workstations.check_findings ({','.join(result)})
            values ({','.join(slots)}) on conflict(id) do nothing""", values)
