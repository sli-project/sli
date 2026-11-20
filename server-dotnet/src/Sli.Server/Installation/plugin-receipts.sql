WITH requested AS MATERIALIZED (
    SELECT DISTINCT unnest(@p0::text[]) AS module_id
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
    FROM sli_agent_snapshot_cycles WHERE module_id=ANY(@p1)
    GROUP BY module_id
) facts GROUP BY module_id
