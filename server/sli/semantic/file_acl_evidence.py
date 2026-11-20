"""Authorised mixed native evidence pages; snapshots never become core events."""
import json
import re

from server.sli.core.database import query_rows
from server.sli.plugins.file_audit.access import require_access

COUNT_LIMIT = 10000


def _payload(statement, params, name):
    rows = query_rows(statement, params)
    value = rows[0][name] if rows else None
    return json.loads(value) if isinstance(value, str) and name != 'watermark' else value


def page(finding_id, *, after_id=0, position=None, watermark=None, limit=20,
         access, fields_allowed, action='view', domain_ids=None, legacy_cursor=False):
    clean_limit = max(1, min(int(limit), 200))
    if finding_id <= 0 or type(after_id) is not int or after_id < 0:
        raise ValueError('invalid_evidence_page')
    if position is not None:
        if (not isinstance(position, dict) or set(position) != {'storage_kind', 'native_key'}
                or position['storage_kind'] not in ('core_event', 'file_audit_snapshot')):
            raise ValueError('invalid_cursor')
        pattern = '[0-9]{20}' if position['storage_kind'] == 'core_event' else '[a-f0-9]{64}'
        if not isinstance(position['native_key'], str) or not re.fullmatch(pattern, position['native_key']):
            raise ValueError('invalid_cursor')
        if position['storage_kind'] == 'core_event':
            after_id = int(position['native_key'])
    watermark = watermark or _payload('select clock_timestamp()::text as watermark', (), 'watermark')
    if not watermark or not isinstance(watermark, str):
        raise ValueError('invalid_cursor')
    allowed = []
    if fields_allowed:
        resources = _payload('select public.read_file_acl_finding_resources_v265(?::bigint,?::bigint[]) as resources',
                             (finding_id, domain_ids), 'resources') or []
        if len(resources) > 128:
            raise PermissionError('file_audit_access_denied')
        for resource in resources:
            try:
                require_access(access, action=action, agent_id=resource['agent_id'],
                    source_instance_id=resource['source_instance_id'], collection_scope_id=resource['collection_scope_id'])
            except PermissionError:
                continue
            allowed.append(resource)
    totals = query_rows('''select count(*) as total from (select id from finding_evidence
        where finding_id=? and created_at<=?::timestamptz limit ?) counted''',
        (finding_id, watermark, COUNT_LIMIT + 1))
    core_count = int(totals[0]['total']) if totals else 0
    core_rows = []
    if not position or position['storage_kind'] == 'core_event':
        core_rows = query_rows('''select fe.id as evidence_id,e.id as event_db_id,e.event_id,channel.value as channel,
          e.time_created_utc,e.event_record_id,s.hostname,fe.evidence_role,fe.note
          from finding_evidence fe left join events_v2_core e on e.id=fe.event_id
          left join storage_v2_channel channel on channel.id=e.channel_id left join servers s on s.id=e.server_id
          where fe.finding_id=? and fe.id>? and fe.created_at<=?::timestamptz order by fe.id limit ?''',
          (finding_id, after_id, watermark, clean_limit + 1))
    native = {'items': [], 'total': 0, 'has_more': False}
    if allowed:
        native = _payload('''select public.read_file_acl_finding_evidence(?::bigint,?::jsonb,?::text,?::integer,
            ?::timestamptz,?::bigint[]) as evidence''',
            (finding_id, json.dumps(allowed), position['native_key'] if position and position['storage_kind'] == 'file_audit_snapshot' else None,
             1 if len(core_rows) > clean_limit else clean_limit, watermark, domain_ids), 'evidence')
    native_count = native.get('total')
    if legacy_cursor and (native_count or native.get('total_lower_bound')):
        raise ValueError('invalid_cursor')
    combined = [row | {'storage_kind': 'core_event', '_native_key': str(row['evidence_id']).zfill(20)} for row in core_rows]
    combined += native['items']
    items = []
    size = 0
    next_position = None
    for row in combined:
        if len(items) == clean_limit or size + len(json.dumps(row, default=str).encode()) > 4194304:
            break
        size += len(json.dumps(row, default=str).encode())
        clean = dict(row)
        key = clean.pop('_native_key')
        items.append(clean)
        next_position = {'storage_kind': clean['storage_kind'], 'native_key': key}
    has_more = len(combined) > len(items) or native['has_more']
    total = core_count + native_count if native_count is not None and core_count <= COUNT_LIMIT else None
    if total is not None and total > COUNT_LIMIT:
        total = None
    result = {'items': items, 'total': total, 'has_more': has_more,
              'watermark': watermark, 'next_position': next_position if has_more else None}
    if total is None:
        result['total_lower_bound'] = core_count + (native_count if native_count is not None else native.get('total_lower_bound') or 0)
    return result
