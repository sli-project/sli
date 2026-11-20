"""Metadata-only evidence for the first unpublished history batch.

Run: python -m server.sli.storage.history_source_diagnostics
Uses existing worker/history credentials; never falls back to admin, copies
history, advances a frontier, or authorizes deletion. The optional archive
check reads verified link-detail blocks within strict byte and row budgets.
Manifest coverage alone is NOT proof that link details exist. This command cannot
repair T064. Results describe one PostgreSQL snapshot and two separate history
frontier observations, not an atomic cross-store snapshot or whole-tail count.
Counts cover production-visible joined links: unknown role IDs are excluded by
the same role join as the copier, not counted as physical orphan occurrences.
History reads use existing 60s server / 65s socket budgets, not a wall-clock SLA.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from datetime import timezone
from pathlib import Path

MAX_EVENTS = 1000
MAX_LINKS = 10000
MAX_MANIFESTS = 64
MAX_ARCHIVE_COMPRESSED_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_RAW_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_ROW_BYTES = 64 * 1024
MAX_ARCHIVE_ROWS = 100000

CORE_SQL = """
select e.id, e.event_id, e.time_created_utc,
       provider.value as provider_name, channel.value as channel
from events_v2_core e
left join storage_v2_provider provider on provider.id=e.provider_id
join storage_v2_channel channel on channel.id=e.channel_id
where e.id > %s order by e.id limit %s
"""
LINK_SQL = """
select expanded.event_id, block.entity_id, expanded.role_id, role.value as link_role
from event_entity_link_blocks_v2 block
cross join lateral unnest(block.event_ids, block.role_ids) expanded(event_id, role_id)
join storage_v2_role role on role.id=expanded.role_id
where block.first_event_id <= %s and block.last_event_id >= %s
  and expanded.event_id = any(%s::bigint[])
order by expanded.event_id, block.entity_id, expanded.role_id limit %s
"""
MANIFEST_SQL = """
select first_event_id, last_event_id, state, archive_kind, object_location,
       compressed_bytes, raw_bytes, row_count, archive_sha256, raw_sha256
from storage_v2_archive_blocks
where archive_kind='link_detail' and last_event_id >= %s and first_event_id <= %s
order by first_event_id, last_event_id, archive_set_id, block_index limit %s
"""


class DetailDiagnosticError(RuntimeError):
    """Archive verification or diagnostic resource budget failed."""


def inspect_archive_details(links, blocks, *, no_archive_ids, archive_ids=None):
    """Verify bounded archive objects and compare identities without returning payloads."""
    expected = {}
    source_keys = set()
    for link in links:
        event_id = int(link['event_id'])
        key = (event_id, int(link['entity_id']), str(link['link_role']))
        if key in source_keys:
            raise DetailDiagnosticError('source_duplicate')
        source_keys.add(key)
        if event_id in no_archive_ids:
            continue
        expected[key] = int(link['role_id'])
    requested = (set(archive_ids) - set(no_archive_ids) if archive_ids is not None
                 else {key[0] for key in expected})
    matched = set()
    if len(blocks) > MAX_MANIFESTS:
        raise DetailDiagnosticError('archive_budget')
    compressed_used = raw_used = row_count = 0
    for block in blocks:
        if (block['state'] != 'published' or not requested
                or int(block['last_event_id']) < min(requested)
                or int(block['first_event_id']) > max(requested)):
            continue
        if block['archive_kind'] != 'link_detail':
            raise DetailDiagnosticError('archive_kind')
        compressed_left = MAX_ARCHIVE_COMPRESSED_BYTES - compressed_used
        raw_left = MAX_ARCHIVE_RAW_BYTES - raw_used
        if (not 0 <= int(block['compressed_bytes']) <= compressed_left
                or not 0 <= int(block['raw_bytes']) <= raw_left
                or not 0 <= int(block['row_count']) <= MAX_ARCHIVE_ROWS - row_count):
            raise DetailDiagnosticError('archive_budget')
        with Path(block['object_location']).open('rb') as stream:
            compressed = stream.read(compressed_left + 1)
        compressed_used += len(compressed)
        if compressed_used > MAX_ARCHIVE_COMPRESSED_BYTES:
            raise DetailDiagnosticError('archive_budget')
        if (len(compressed) != int(block['compressed_bytes'])
                or hashlib.sha256(compressed).hexdigest() != _digest_hex(block['archive_sha256'])):
            raise DetailDiagnosticError('archive_compressed_invalid')
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
            raw = stream.read(raw_left + 1)
        raw_used += len(raw)
        if raw_used > MAX_ARCHIVE_RAW_BYTES:
            raise DetailDiagnosticError('archive_budget')
        if (len(raw) != int(block['raw_bytes'])
                or hashlib.sha256(raw).hexdigest() != _digest_hex(block['raw_sha256'])):
            raise DetailDiagnosticError('archive_raw_invalid')
        block_rows = 0
        stream = io.BytesIO(raw)
        while line := stream.readline(MAX_ARCHIVE_ROW_BYTES + 1):
            if len(line) > MAX_ARCHIVE_ROW_BYTES:
                raise DetailDiagnosticError('archive_budget')
            block_rows += 1
            row_count += 1
            if row_count > MAX_ARCHIVE_ROWS or block_rows > int(block['row_count']):
                raise DetailDiagnosticError('archive_row_count')
            payload = json.loads(line)
            if payload.get('kind') != 'link_detail' or not isinstance(payload.get('row'), dict):
                raise DetailDiagnosticError('archive_envelope')
            row = payload['row']
            event_id = int(row['event_id'])
            if event_id not in requested:
                continue
            key = (event_id, int(row['entity_id']), str(row['link_role']))
            if key not in expected:
                raise DetailDiagnosticError('archive_extra_link')
            if key in matched:
                raise DetailDiagnosticError('archive_duplicate')
            if int(row['role_id']) != expected[key]:
                raise DetailDiagnosticError('archive_role_mismatch')
            matched.add(key)
        if block_rows != int(block['row_count']):
            raise DetailDiagnosticError('archive_row_count')
    missing = set(expected) - matched
    missing_ids = sorted({key[0] for key in missing})
    return {'detail_presence_checked': True, 'missing_detail_links': len(missing),
            'missing_detail_events': len(missing_ids),
            'sample_missing_detail_event_ids': missing_ids[:5]}


def _digest_hex(value):
    return value.lower() if isinstance(value, str) else bytes(value).hex()


def summarize(cores, links, blocks, *, no_archive_ids, truncated=False):
    """Count compact occurrences with no published covering manifest, not data loss."""
    result = {
        'status': 'diagnostic', 'scope': 'first_unpublished_batch_metadata_only',
        'link_scope': 'production_visible_role_join',
        'detail_presence_checked': False, 'deletion_authorized': False,
        'truncated': truncated, 'observed_events': len(cores),
        'observed_link_rows': len(links), 'observed_manifest_rows': len(blocks),
        'missing_published_manifest_links': None,
        'missing_published_manifest_events': None,
        'manifest_covered_detail_unchecked_links': None,
        'unpublished_manifest_events': None, 'no_archive_links': None,
        'sample_event_ids': [], 'missing_time_min_utc': None,
        'missing_time_max_utc': None,
    }
    if truncated:
        return {**result, 'reason': 'diagnostic_row_budget_exceeded'}
    missing = []
    covered = no_archive = 0
    unpublished = set()
    for link in links:
        event_id = int(link['event_id'])
        if event_id in no_archive_ids:
            no_archive += 1
            continue
        matches = [block for block in blocks
                   if int(block['first_event_id']) <= event_id <= int(block['last_event_id'])]
        if any(block['state'] == 'published' for block in matches):
            covered += 1
        else:
            missing.append(event_id)
            if matches:
                unpublished.add(event_id)
    missing_ids = set(missing)
    times = [core['time_created_utc'].astimezone(timezone.utc).isoformat()
             for core in cores if int(core['id']) in missing_ids]
    return {
        **result,
        'reason': 'published_manifest_missing' if missing else 'detail_presence_not_checked',
        'missing_published_manifest_links': len(missing),
        'missing_published_manifest_events': len(missing_ids),
        'manifest_covered_detail_unchecked_links': covered,
        'unpublished_manifest_events': len(unpublished), 'no_archive_links': no_archive,
        'sample_event_ids': sorted(missing_ids)[:5],
        'missing_time_min_utc': min(times) if times else None,
        'missing_time_max_utc': max(times) if times else None,
    }


def inspect_batch(*, connect, read_frontier, catalog, batch_events=MAX_EVENTS, check_archive=False):
    """Bound returned rows and SQL; optionally verify bounded archive objects."""
    if type(batch_events) is not int or not 1 <= batch_events <= MAX_EVENTS:
        raise ValueError('diagnostic_batch_size_invalid')
    before = int(read_frontier())
    with connect() as conn, conn.cursor() as cur:
        cur.execute('set transaction isolation level repeatable read read only')
        cur.execute('set local statement_timeout = 5000')
        cur.execute('set local lock_timeout = 1000')
        cur.execute('select current_user as role')
        if cur.fetchone()['role'] != 'adlog_storage_worker':
            raise RuntimeError('diagnostic_worker_role_required')
        cur.execute(CORE_SQL, (before, batch_events))
        cores = [dict(row) for row in cur.fetchall()]
        links, blocks = [], []
        if cores:
            ids = [int(row['id']) for row in cores]
            cur.execute(LINK_SQL, (max(ids), min(ids), ids, MAX_LINKS + 1))
            links = [dict(row) for row in cur.fetchall()]
            cur.execute(MANIFEST_SQL, (min(ids), max(ids), MAX_MANIFESTS + 1))
            blocks = [dict(row) for row in cur.fetchall()]
    no_archive_ids = set()
    for core in cores:
        entry = catalog(int(core.get('event_id', 0)), core.get('channel'), core.get('provider_name'))
        promotion = (((entry or {}).get('lifecycle') or {}).get('promotion') or {})
        if promotion.get('archive_requirement') == 'no_archive':
            no_archive_ids.add(int(core['id']))
    truncated = len(links) > MAX_LINKS or len(blocks) > MAX_MANIFESTS
    result = summarize(cores, links[:MAX_LINKS], blocks[:MAX_MANIFESTS],
                       no_archive_ids=no_archive_ids, truncated=truncated)
    if check_archive and not truncated:
        result.update(inspect_archive_details(links, blocks, no_archive_ids=no_archive_ids,
                                              archive_ids={int(core['id']) for core in cores}))
        result['scope'] = 'first_unpublished_batch_archive_details'
        missing_ids = set(result['sample_missing_detail_event_ids'])
        times = [core['time_created_utc'].astimezone(timezone.utc).isoformat()
                 for core in cores if int(core['id']) in missing_ids]
        result['sample_missing_detail_time_min_utc'] = min(times) if times else None
        result['sample_missing_detail_time_max_utc'] = max(times) if times else None
        result['reason'] = ('archive_details_missing' if result['missing_detail_links']
                            else 'archive_details_present')
    after = int(read_frontier())
    result.update(frontier_before=before, frontier_after=after,
                  frontier_unchanged=before == after, batch_event_limit=batch_events,
                  link_row_limit=MAX_LINKS, manifest_row_limit=MAX_MANIFESTS)
    if before != after:
        result['reason'] = 'history_frontier_changed_during_diagnostic'
        if check_archive:
            for key in ('missing_detail_links', 'missing_detail_events', 'sample_missing_detail_event_ids',
                        'sample_missing_detail_time_min_utc', 'sample_missing_detail_time_max_utc'):
                result.pop(key, None)
            result['detail_presence_checked'] = False
    return result


def _connect_worker_readonly():
    """Use only configured worker credentials, with no protected-admin fallback."""
    import psycopg
    from psycopg.rows import dict_row

    from server.sli.core.secret_files import postgres_secret_parts

    parts = postgres_secret_parts('ADLOG_STORAGE_V2_WORKER_DSN')
    if not parts:
        raise RuntimeError('worker_connection_required')
    parts = dict(parts)
    options = str(parts.get('options') or '').strip()
    parts.update(connect_timeout=5, application_name='sli_history_source_diagnostic',
                 options=(options + ' -c default_transaction_read_only=on'
                          ' -c statement_timeout=5000 -c lock_timeout=1000').strip())
    conn = psycopg.connect(**parts, row_factory=dict_row)
    try:
        with conn.cursor() as cur:
            cur.execute('set role adlog_storage_worker')
        conn.commit()
        return conn
    except Exception:
        conn.close()
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--batch-events', type=int, default=MAX_EVENTS, metavar='1..1000')
    parser.add_argument('--check-archive', action='store_true', help='verify bounded link-detail archive objects')

    args = parser.parse_args(argv)
    if not 1 <= args.batch_events <= MAX_EVENTS:
        parser.error('--batch-events must be between 1 and 1000')
    # Refuse absent worker configuration before loading runtime collaborators.
    if not (os.environ.get('ADLOG_STORAGE_V2_WORKER_DSN', '').strip()
            or 'ADLOG_STORAGE_V2_WORKER_DSN_FILE' in os.environ):
        print(json.dumps({'status': 'inconclusive', 'reason': 'worker_connection_required'}))
        return 2
    try:
        from server.sli.events.event_catalog import lookup_event_catalog
        from server.sli.storage import permanent_fact_history as history

        port = history.configured_read_port()
        if port is None:
            raise RuntimeError('diagnostic_history_port_required')
        result = inspect_batch(connect=_connect_worker_readonly,
                               read_frontier=lambda: history.next_after_id(port),
                               catalog=lookup_event_catalog, batch_events=args.batch_events,
                               check_archive=args.check_archive)
    except DetailDiagnosticError as error:
        reason = ('diagnostic_archive_budget_exceeded' if str(error) == 'archive_budget'
                  else 'diagnostic_archive_integrity_or_identity_failed')
        print(json.dumps({'status': 'inconclusive', 'reason': reason}))
        return 2
    except Exception as error:
        # Never echo arbitrary SQL, paths, connection strings or archive payloads.
        reason = {'42501': 'diagnostic_permission_denied',
                  '57014': 'diagnostic_statement_timeout',
                  '55P03': 'diagnostic_lock_timeout'}.get(getattr(error, 'sqlstate', None),
                                                        'diagnostic_read_failed')
        print(json.dumps({'status': 'inconclusive', 'reason': reason}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 2 if result['truncated'] or not result['frontier_unchanged'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
