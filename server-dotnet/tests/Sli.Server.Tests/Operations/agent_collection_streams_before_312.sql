with requested as materialized (
    select * from jsonb_to_recordset(@requested::jsonb) as x(
        agent_id uuid,module_id text,revision text,channel text,snapshot boolean)
)
select wanted.agent_id::text,wanted.module_id,wanted.revision,wanted.channel,
       latest.received_at as last_packet_at,imported.last_import_at,
       pending.pending_since,
       case when wanted.module_id='sli.file-audit' then (
           select case when payload.packet#>'{context,read_error}'='null'::jsonb then false
               when payload.packet#>>'{context,read_error}' in
                   ('file_audit_read_failed','file_audit_journal_gap') then true
               else null end
           from sli_agent_packet_inbox payload where payload.packet_id=latest.packet_id
       ) else latest.collection_read_error end as read_error,
       pending.historical_unimported_packets,pending.historical_error_at
from requested wanted
left join lateral (
    select r.packet_id,r.received_at,i.collection_read_error
    from sli_agent_receipts r join sli_agent_packet_inbox i using(packet_id)
    where r.agent_id=wanted.agent_id and r.module_id=wanted.module_id
      and i.collection_revision=wanted.revision
      and i.collection_channel is not distinct from wanted.channel
    order by r.received_at desc,r.sequence desc limit 1
) latest on true
left join sli_agent_stream_import_health imported
  on imported.agent_id=wanted.agent_id and imported.module_id=wanted.module_id
 and imported.revision=wanted.revision
 and imported.channel is not distinct from wanted.channel
 and latest.packet_id is not null
left join lateral (
    select min(r.received_at) filter(where historical.packet_id is null) as pending_since,
           count(*) filter(where historical.packet_id is not null) as historical_unimported_packets,
           min(historical.quarantined_at) as historical_error_at
    from sli_agent_packet_inbox i join sli_agent_receipts r using(packet_id)
    left join sli_agent_packet_quarantine historical on historical.packet_id=r.packet_id
      and historical.reason_code in ('source_event_allocation_hash_mismatch','published_source_event_hash_mismatch')
      and r.received_at < now() - interval '7 days'
    where i.imported_at is null
      and r.agent_id=wanted.agent_id and r.module_id=wanted.module_id
      and i.collection_revision=wanted.revision
      and i.collection_channel is not distinct from wanted.channel
) pending on true
where not wanted.snapshot
union all
select wanted.agent_id::text,wanted.module_id,wanted.revision,null,
       max(coalesce(c.completed_at,c.created_at)),max(c.published_at),
       min(c.created_at) filter(where c.publication_state='pending'),false,0,null::timestamptz
from requested wanted left join sli_agent_snapshot_cycles c
  on c.agent_id=wanted.agent_id and c.module_id=wanted.module_id
 and c.policy->>'policy_revision'=wanted.revision
where wanted.snapshot
group by wanted.agent_id,wanted.module_id,wanted.revision
