"""Bounded attested file measurements; never proof of historical execution.

The enclosing authenticated collection packet supplies provenance, not an
independent server-side Authenticode verification. Legacy absence stays unknown.
"""
from __future__ import annotations

import hashlib
import re
from copy import deepcopy
from datetime import datetime

CONTRACT = 'sli.workstation-file-signature.v1'
MAX_ENTRIES = 2
_FIELDS = {'contract', 'record_id', 'source_sha256', 'path', 'measurement'}
_MEASUREMENT = {'scope', 'observed_at_utc', 'status', 'reason', 'sha256_before',
                'sha256_after', 'identity_before', 'identity_after', 'signer_sha256', 'kind'}
_REASONS = {'timeout', 'unsupported', 'unsafe_path', 'too_large', 'changed', 'verification_failed'}
_RESERVED = re.compile(r'(?:con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?', re.IGNORECASE)


def local_path(value):
    """Lexical eligibility only: native reader must also reject remote/reparse paths."""
    if not isinstance(value, str) or value != value.strip():
        # Shared process facts strip Unicode edge whitespace. Do not attach
        # an exact-path measurement if that identity would change downstream.
        return None
    try:
        size = len(value.encode('utf-8'))
    except UnicodeEncodeError:
        return None
    if not 1 <= size <= 512 or not re.match(r'^[A-Za-z]:\\', value):
        return None
    parts = value[3:].split('\\')
    if any(not part or part in ('.', '..') or part.endswith((' ', '.'))
           or _RESERVED.fullmatch(part) or '~' in part
           or any(ord(c) < 32 or ord(c) == 127 or c in '/:"<>|?*%' for c in part)
           for part in parts):
        return None
    return value


def _time(value):
    try:
        result = value if isinstance(value, datetime) else datetime.fromisoformat(value)
        if result.utcoffset() is None:
            raise ValueError
        return result
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError('workstation_signature_timestamp_invalid') from exc


def _hash(value):
    return isinstance(value, str) and re.fullmatch(r'[a-f0-9]{64}', value) is not None


def unavailable(reason, now):
    if not isinstance(reason, str) or reason not in _REASONS:
        raise ValueError('workstation_signature_reason_invalid')
    return {'scope': 'file_at_measurement', 'observed_at_utc': _time(now).isoformat(),
                'status': 'unavailable', 'reason': reason, 'sha256_before': None, 'sha256_after': None,
                'identity_before': None, 'identity_after': None, 'signer_sha256': None, 'kind': None}


def validate_measurement(value, *, packet_time=None):
    if not isinstance(value, dict) or set(value) != _MEASUREMENT or value['scope'] != 'file_at_measurement':
        raise ValueError('workstation_signature_measurement_invalid')
    if not isinstance(value['observed_at_utc'], str) or len(value['observed_at_utc']) > 40:
        raise ValueError('workstation_signature_timestamp_invalid')
    measured = _time(value['observed_at_utc'])
    if packet_time is not None and not -1 <= (measured - _time(packet_time)).total_seconds() <= 5:
        raise ValueError('workstation_signature_timestamp_invalid')
    status = value['status']
    if status == 'unavailable':
        if (not isinstance(value['reason'], str) or value['reason'] not in _REASONS or any(value[k] is not None for k in
                ('sha256_before', 'sha256_after', 'identity_before', 'identity_after', 'signer_sha256', 'kind'))):
            raise ValueError('workstation_signature_measurement_invalid')
    elif status in ('signed', 'unsigned'):
        if (value['reason'] is not None or not _hash(value['sha256_before'])
                or value['sha256_after'] != value['sha256_before'] or not _hash(value['identity_before'])
                or value['identity_after'] != value['identity_before']
                or (status == 'signed' and (value['kind'] not in ('embedded', 'catalog') or not _hash(value['signer_sha256'])))
                or (status == 'unsigned' and (value['kind'] != 'none' or value['signer_sha256'] is not None))):
            raise ValueError('workstation_signature_measurement_invalid')
    else:
        raise ValueError('workstation_signature_measurement_invalid')
    return deepcopy(value)


def validate_entries(entries, rows, *, packet_time):
    if entries is None:
        return {}
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        raise ValueError('workstation_signature_entries_invalid')
    result = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != _FIELDS:
            raise ValueError('workstation_signature_entry_invalid')
        rid = entry['record_id']
        if (entry['contract'] != CONTRACT or type(rid) is not int or rid < 0 or rid in result
                or local_path(entry['path']) is None or not _hash(entry['source_sha256'])):
            raise ValueError('workstation_signature_binding_invalid')
        matches = [row for row in rows if row.get('record_id') == rid]
        if len(matches) != 1:
            raise ValueError('workstation_signature_binding_invalid')
        row = matches[0]
        if (row.get('event_id') != 4688 or row.get('channel') != 'Security'
                or row.get('provider_name') != 'Microsoft-Windows-Security-Auditing'
                or row.get('process_path') != entry['path']
                or hashlib.sha256(row['xml'].encode()).hexdigest() != entry['source_sha256']):
            raise ValueError('workstation_signature_binding_invalid')
        validate_measurement(entry['measurement'], packet_time=packet_time)
        result[rid] = deepcopy(entry)
    return result


def packet_entries(packet, rows):
    """Bind extension to native XML, not a collector-supplied display path.

    Called only within existing authenticated/policy admission and again before
    projection; does not grant collection authority or authenticate a packet.
    """
    entries = packet.get('context', {}).get('workstations', {}).get('process_signatures')
    if entries is None or entries == []:
        return {}
    # Reject unbounded extension before any XML parsing.
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        raise ValueError('workstation_signature_entries_invalid')
    from server.sli.storage.xml_safety import parse_bounded_xml
    from sli_collect.eventlog import NS

    bound = []
    for row in rows:
        if not any(isinstance(entry, dict) and entry.get('record_id') == row.get('record_id') for entry in entries):
            continue
        root = parse_bounded_xml(row['xml'])
        system = root.find('e:System', NS)
        if system is None:
            raise ValueError('workstation_signature_binding_invalid')
        provider = system.find('e:Provider', NS)
        native_id = system.findtext('e:EventID', namespaces=NS)
        native_record = system.findtext('e:EventRecordID', namespaces=NS)
        native_channel = system.findtext('e:Channel', namespaces=NS)
        if (native_id != '4688' or native_record != str(row.get('record_id'))
                or native_channel != 'Security' or provider is None
                or provider.get('Name') != 'Microsoft-Windows-Security-Auditing'):
            raise ValueError('workstation_signature_binding_invalid')
        paths = [node.text for node in root.findall('e:EventData/e:Data', NS)
                 if node.get('Name') == 'NewProcessName']
        if len(paths) != 1:
            raise ValueError('workstation_signature_binding_invalid')
        bound.append({**row, 'process_path': paths[0]})
    return validate_entries(entries, bound, packet_time=packet['header']['observed_at_utc'])
