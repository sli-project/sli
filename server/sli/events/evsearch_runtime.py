"""Read-only evsearch.v1 runtime for the existing published event slice.

No grants, projection, storage switch or retention settings are installed here.
Unsupported historical policies fail closed: a hot-only search is never
substituted. Missing semantic identities produce honest singleton groups.
"""
from __future__ import annotations

from dataclasses import asdict, replace
from datetime import timedelta
import json
from threading import Lock

from server.sli.access.access_control_v4 import effective_access
from server.sli.core.database import QueryTimeoutError, query_rows_bounded
from server.sli.events import evsearch_history
from server.sli.events.evsearch_contract import ACCESS_KEY, ContractError, MAX_PAGE_SIZE
from server.sli.events.evsearch_grouping import GroupSnapshotStore
from server.sli.events.evsearch_normalizer import normalize_request
from server.sli.events.evsearch_postgres import DEFAULT_FIELDS, read_hot_capture
from server.sli.events.evsearch_snapshot import SnapshotError, _json_default
from server.sli.reporting.read_timeout import remaining_read_ms, report_read_budget
from server.sli.reporting.reporting_v4_definitions import _definition_columns, _json_mapping
from server.sli.storage.runtime_storage import StorageRouteAuthorizationError, StorageRouteConsumer, resolve_storage_route
from server.sli.storage.storage_policy import load_storage_policy

# Retained encoded snapshots <=64 MiB; only ONE operation may allocate captures
# or decoded copies at a time. Two input captures <=16 MiB each, checked jointly
# before grouping; retained output <=16 MiB. No per-request store or context map.
RETAINED_BYTES = 64 * 1024 * 1024


class EventSearchRuntime:
    def __init__(self):
        self.store = GroupSnapshotStore(max_total_bytes=RETAINED_BYTES)
        self._operation = Lock()

    def _publication(self, principal, remaining):
        access = effective_access(principal)  # fresh, not the session UI cache
        remaining()
        if 'events.view' not in (access.get('capabilities') or []):
            raise PermissionError('evsearch.policy_denied')
        report = next((r for r in access.get('reports', [])
                       if r.get('report_key') == ACCESS_KEY and r.get('allowed')), None)
        if report is None:
            raise PermissionError('evsearch.policy_denied')
        budget = remaining()
        if budget <= 350:
            raise SnapshotError('snapshot_timeout')
        rows = query_rows_bounded(
            "select r.definition_json,d.dataset_key,d.fields_json,r.version "
            "from report_registry_v4 r join report_datasets_v4 d on d.id=r.dataset_id "
            "where r.report_key=? and r.version=? and r.status='published' and d.status='published' limit 1",
            (ACCESS_KEY, report.get('version')), statement_timeout_ms=budget - 250, wall_timeout_ms=budget,
        )
        remaining()
        if not rows:
            raise PermissionError('evsearch.policy_denied')
        publication = rows[0]
        try:
            _definition_columns(_json_mapping(publication.get('definition_json')),
                                {f['key']: f for f in publication.get('fields_json') or []})
        except (ValueError, TypeError, KeyError):
            raise PermissionError('evsearch.policy_denied') from None
        return access, publication

    @staticmethod
    def _admit(authorization):
        resolve_storage_route(authorization=authorization, consumer=StorageRouteConsumer.EVENT_SEARCH)
        try:
            enabled = evsearch_history.history.primary_read_enabled()
        except (ValueError, RuntimeError):
            enabled = False
        if not enabled:
            raise evsearch_history.HistoryError('history_unavailable')

    def execute(self, operation, body, *, principal, authorization=None):
        if (not isinstance(principal, dict) or principal.get('type') != 'session'
                or type(principal.get('id')) is not int or principal['id'] <= 0):
            raise PermissionError('evsearch.policy_denied')
        if not isinstance(body, dict) or operation not in {'query', 'page', 'members'}:
            raise ContractError('invalid_request')
        if not self._operation.acquire(blocking=False):
            raise SnapshotError('snapshot_limit_exceeded')
        try:
            with report_read_budget(timeout_ms=self.store.timeout_seconds * 1000):
                return self._execute(operation, body, principal, authorization)
        finally:
            self._operation.release()

    def _execute(self, operation, body, principal, authorization):
        deadline = self.store.clock() + min(self.store.timeout_seconds, remaining_read_ms() / 1000)
        as_of = self.store.utcnow()
        owner = principal['id']

        def remaining():
            value = int((deadline - self.store.clock()) * 1000)
            if value <= 0:
                raise SnapshotError('snapshot_timeout')
            return min(value, remaining_read_ms())

        execution_id = None
        if operation == 'query':
            search = normalize_request(body, now=as_of)
            fields = DEFAULT_FIELDS
        else:
            keys = {'execution_id', 'cursor', 'page_size'} | ({'group_key'} if operation == 'members' else set())
            if set(body) - keys or not isinstance(body.get('execution_id'), str) or not 0 < len(body['execution_id']) <= 128:
                raise ContractError('invalid_request')
            if 'cursor' in body and (not isinstance(body['cursor'], str) or not 0 < len(body['cursor']) <= 2048):
                raise ContractError('invalid_cursor')
            if 'page_size' in body and (type(body['page_size']) is not int or not 1 <= body['page_size'] <= MAX_PAGE_SIZE):
                raise ContractError('invalid_request')
            execution_id = body['execution_id']
            context = self.store.execution_context(execution_id, owner_id=owner)
            search = normalize_request(context['request'], now=as_of)
            if 'page_size' in body:
                search = replace(search, page_size=body['page_size'])
            fields = tuple(context['fields'])
        try:
            self._admit(authorization)
            access, publication = self._publication(principal, remaining)
            args = dict(owner_id=owner, search=search, access=access, publication=publication,
                        fields=fields, revision='evsearch.runtime.v1')
            if operation == 'query':
                cutoff = as_of - timedelta(days=load_storage_policy().db_retention_days)
                remaining()
                # Both complete bounded captures cover the same window. Age is
                # NOT proof of publication; never truncate PG at the cutoff.
                hot = read_hot_capture(search, access=access, publication=publication, fields=fields,
                                       limit=self.store.max_events, timeout_ms=remaining())
                cold = evsearch_history.ClickHouseHistoryReader(
                    query_rows=evsearch_history._query_rows, clock=self.store.clock,
                ).read(search, access=access, publication=publication, fields=fields,
                       authorization=authorization, limit=self.store.max_events, timeout_ms=remaining()).capture
                remaining()
                if cold is None:
                    raise ContractError('storage_integrity_error')
                if len(hot.items) + len(cold.items) > self.store.max_events:
                    raise SnapshotError('snapshot_limit_exceeded')
                captured_bytes = sum(len(json.dumps(c.items, separators=(',', ':'), default=_json_default).encode())
                                     for c in (hot, cold))
                if captured_bytes > self.store.max_snapshot_bytes:
                    raise SnapshotError('snapshot_limit_exceeded')
                page = self.store.start(**args, hot=hot, cold=cold, retention_boundary=cutoff,
                                        evidence=(), deadline=deadline, as_of=as_of)
                execution_id = page.execution_id
            elif operation == 'page':
                page = self.store.page(execution_id, **args, cursor=body.get('cursor'))
            else:
                page = self.store.members(execution_id, **args, group_key=body.get('group_key'), cursor=body.get('cursor'))
            remaining()
            result = asdict(page)
            context = self.store.execution_context(execution_id, owner_id=owner)
            result.update(contract_version='evsearch.v1', period=context['request']['period'],
                          retention_boundary=context['retention_boundary'])
            if operation == 'members':
                for row in result['items']:
                    row['source_payload_state'] = row['fields'].get('source_payload_state', 'unknown')
            # A cold reader/PG success is never proof of source continuity.
            result['coverage'] = 'unknown'
            result = json.loads(json.dumps(result, default=_json_default))
            remaining()
            return result
        except (PermissionError, ContractError, QueryTimeoutError, StorageRouteAuthorizationError):
            # A revoked/disabled execution cannot revive if the switch/grant is
            # restored. Owner was checked before entering this block.
            if execution_id is not None:
                with self.store._lock:
                    if execution_id in self.store._entries:
                        self.store._remove(execution_id)
            raise



RUNTIME = EventSearchRuntime()
