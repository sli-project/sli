"""Read-only receipt/import facts; timestamps never assert current health."""
from __future__ import annotations

from psycopg import Error

from server.sli.core.database import query_rows_bounded

# Server-owned dispatch bindings: agents.consumer and snapshot_stream.MODULE_FAMILIES.
# Sigma analyses retained events; it has no independent agent receipt stream.
PLUGIN_MODULES = {
    'sli.ad': ('sli.windows.ad-dc', 'sli.windows.ad-dc-history', 'sli.ad-snapshot'),
    'sli.gpo': ('sli.gpo-snapshot',),
    'sli.file-audit': ('sli.file-audit',),
    'sli.workstations': ('sli.workstations',),
    'sli.remote-access': ('sli.vpn-nps', 'sli.radius-accounting'),
}

# Latest receipt plus exact newest-import prefix; missing modules use FULL
# historical import fallback. Snapshot facts remain separate. No payload reads.
# The existing runtime SELECT grants suffice. The timeout bounds work, not the
# amount of history scanned; no hard history bound or latency SLA is claimed.
_RECEIPTS_SQL = """
WITH requested AS MATERIALIZED (
    SELECT DISTINCT unnest(?::text[]) AS module_id
), receipt_facts AS MATERIALIZED (
    SELECT requested.module_id, latest.received_at AS last_received_at
    FROM requested CROSS JOIN LATERAL (
        SELECT r.received_at FROM sli_agent_receipts r
        WHERE r.module_id=requested.module_id
        ORDER BY r.received_at DESC LIMIT 1
    ) latest
), import_prefix AS MATERIALIZED (
    SELECT packet_id,imported_at FROM sli_agent_packet_inbox
    WHERE imported_at IS NOT NULL
    ORDER BY imported_at DESC,packet_id LIMIT 1024
), prefix_imports AS MATERIALIZED (
    SELECT r.module_id,max(p.imported_at) AS last_imported_at
    FROM import_prefix p JOIN sli_agent_receipts r USING(packet_id)
    WHERE r.module_id IN (SELECT module_id FROM receipt_facts)
      AND r.module_id NOT IN ('sli.ad-snapshot','sli.gpo-snapshot')
    GROUP BY r.module_id
), missing_imports AS MATERIALIZED (
    SELECT f.module_id FROM receipt_facts f
    WHERE f.module_id NOT IN ('sli.ad-snapshot','sli.gpo-snapshot')
      AND NOT EXISTS (SELECT 1 FROM prefix_imports p WHERE p.module_id=f.module_id)
), fallback_imports AS (
    -- No date, receipt-order or row-count restriction: full exact history.
    -- EXISTS provides an explicit empty-fallback gate, to verify in EXPLAIN.
    SELECT r.module_id,max(i.imported_at) AS last_imported_at
    FROM sli_agent_receipts r JOIN sli_agent_packet_inbox i USING(packet_id)
    WHERE EXISTS (SELECT 1 FROM missing_imports)
      AND r.module_id IN (SELECT module_id FROM missing_imports)
      AND i.imported_at IS NOT NULL
    GROUP BY r.module_id
)
SELECT module_id,max(last_received_at) AS last_received_at,
       max(last_imported_at) AS last_imported_at,
       max(last_snapshot_completed_at) AS last_snapshot_completed_at
FROM (
    SELECT module_id,last_received_at,null::timestamptz AS last_imported_at,
           null::timestamptz AS last_snapshot_completed_at FROM receipt_facts
    UNION ALL
    SELECT module_id,null::timestamptz,last_imported_at,null::timestamptz FROM prefix_imports
    UNION ALL
    SELECT module_id,null::timestamptz,last_imported_at,null::timestamptz FROM fallback_imports
    UNION ALL
    SELECT module_id,null::timestamptz,
           max(published_at) FILTER(WHERE publication_state='published'),
           max(completed_at) FILTER(WHERE transport_state='complete')
    FROM sli_agent_snapshot_cycles WHERE module_id=ANY(?)
    GROUP BY module_id
) facts GROUP BY module_id
"""
TIMESTAMPS = ('last_received_at', 'last_imported_at', 'last_snapshot_completed_at')


def read_plugin_receipts(plugin_ids):
    keys = list(dict.fromkeys(plugin_ids))
    modules = sorted({module for key in keys for module in PLUGIN_MODULES.get(key, ())})
    result = {key: dict(state='no_receipts' if key in PLUGIN_MODULES else 'not_supported',
                        **dict.fromkeys(TIMESTAMPS)) for key in keys}
    if not modules:
        return result
    try:
        rows = query_rows_bounded(_RECEIPTS_SQL, (modules, modules), statement_timeout_ms=3000, wall_timeout_ms=4000)
    except (Error, RuntimeError):
        for key in keys:
            if key in PLUGIN_MODULES:
                result[key]['state'] = 'unavailable'
        return result
    for key in keys:
        matched = [row for row in rows if row['module_id'] in PLUGIN_MODULES.get(key, ())]
        for field in TIMESTAMPS:
            value = max((row[field] for row in matched if row.get(field) is not None), default=None)
            result[key][field] = value.isoformat() if value is not None else None
        if any(result[key][field] is not None for field in TIMESTAMPS):
            result[key]['state'] = 'observed'
    return result

