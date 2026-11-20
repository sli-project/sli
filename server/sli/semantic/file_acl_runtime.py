"""Bounded native Everyone input in the existing transaction-owned QW conveyor."""
from collections import defaultdict
import json

from server.sli.semantic import file_acl_input
from server.sli.semantic.file_acl import classify_acl_result


def _json_call(cur, statement, params):
    cur.execute(statement + ' as payload', params)
    row = cur.fetchone() or {}
    value = row.get('payload')
    return json.loads(value) if isinstance(value, str) else value


def verify_signal(cur, signal):
    """Rebuild the whole immutable portion and independently recompute native facts."""
    file_acl_input.validate_signal(signal)
    resource = signal.acl_context['resource']
    portion = _json_call(cur, 'select public.read_file_acl_portion_v265(%s::jsonb,%s)',
                         (json.dumps(resource), signal.acl_context['portion_id']))
    rebuilt = file_acl_input.signal_from_portion(portion)
    if (rebuilt.signal_id != signal.signal_id
            or json.loads(json.dumps(rebuilt.document)) != json.loads(json.dumps(signal.document))):
        raise RuntimeError('file_acl_signal_conflict')
    for member in signal.acl_context['members']:
        bundle = _json_call(cur, 'select public.read_file_acl_result_by_id(%s::jsonb,%s,%s)',
                           (json.dumps(resource), member['result_id'], member['result_sha256']))
        if not bundle or bundle.get('status') != 'verified':
            raise RuntimeError('file_acl_native_verdict_blocked')
        config = dict(bundle['config'])
        config.setdefault('service_account_exclusions', [])
        snapshot = bundle['snapshot'] | {'agent_id': resource['agent_id'], 'source_instance_id': resource['source_instance_id']}
        native = classify_acl_result(bundle['result'], snapshot=snapshot, config=config,
                                     installation_id=resource['installation_id'])
        if native['severity'] != 'medium' or native['resource_key'] != signal.entity_key:
            raise RuntimeError('file_acl_native_verdict_conflict')
    return rebuilt


def run_once(cur, *, resource, now):
    """No commit: prepare, signal, jobs and processed checkpoint share caller tx."""
    from server.sli.semantic.qw_input import enqueue_qw_signal_risk_jobs

    key = file_acl_input.resource_key(resource)
    cur.execute("set local statement_timeout='20s'")
    cur.execute("set local lock_timeout='1s'")
    cur.execute('select pg_advisory_xact_lock(hashtextextended(%s,0))', (key,))
    portions = _json_call(cur, 'select public.read_pending_file_acl_portions_v265(%s::jsonb)', (json.dumps(resource),))
    page = {'diagnostics': {}, 'has_more': bool(portions), 'byte_count': 0}
    if not portions:
        page = _json_call(cur, 'select public.read_file_acl_results(%s::jsonb,null,32)', (json.dumps(resource),))
        groups = defaultdict(list)
        for bundle in page['items']:
            groups[bundle['provenance']['command_id']].append({
                'result_id': bundle['result']['result_id'], 'result_sha256': bundle['result_sha256']})
        portions = [_json_call(cur, 'select public.prepare_file_acl_portion_v265(%s::jsonb,%s::jsonb)',
                              (json.dumps(resource), json.dumps(members))) for _, members in sorted(groups.items())]
    jobs = 0
    for portion in portions:
        signal = file_acl_input.signal_from_portion(portion)
        admitted = enqueue_qw_signal_risk_jobs(cur, signal=signal)
        if not admitted:
            raise RuntimeError('file_acl_required_jobs_missing')
        checkpoint = _json_call(cur, 'select public.advance_file_acl_checkpoint_v265(%s::jsonb,%s,%s)',
                                (json.dumps(resource), portion['portion_id'], signal.signal_id))
        if checkpoint is not True:
            raise RuntimeError('file_acl_checkpoint_denied')
        jobs += len(admitted)
    return {'jobs': jobs, 'portions': len(portions), 'diagnostics': page['diagnostics'],
            'has_more': page['has_more'], 'byte_count': page['byte_count']}
