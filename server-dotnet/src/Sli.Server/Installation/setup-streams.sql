with requested as materialized (
    select * from jsonb_to_recordset(@p0::jsonb) as x(
        agent_id uuid,module_id text,revision text,channel text,snapshot boolean)
), pending as materialized (
    select r.agent_id,r.module_id,i.collection_revision,i.collection_channel,
           min(r.received_at) filter(where rejected.packet_id is null) as pending_since,
           count(*) filter(where historical.packet_id is not null) as historical_unimported_packets,
           min(historical.quarantined_at) as historical_error_at,
           (array_agg(jsonb_build_object('reason',rejected.reason_code,'at',rejected.quarantined_at)
               order by rejected.quarantined_at desc) filter(where rejected.packet_id is not null))[1] as import_failure
    from sli_agent_packet_inbox i
    cross join lateral (
        -- Fence the unique packet probe: a bad estimate must not turn an
        -- 8000-packet queue into a scan of the complete receipt history.
        select packet_id,agent_id,module_id,received_at from sli_agent_receipts
        where packet_id=i.packet_id offset 0
    ) r
    left join sli_agent_packet_quarantine historical on historical.packet_id=r.packet_id
      and historical.reason_code in ('source_event_allocation_hash_mismatch','published_source_event_hash_mismatch')
      and r.received_at < now() - interval '7 days'
    left join sli_agent_packet_quarantine rejected on rejected.packet_id=r.packet_id
    where i.imported_at is null
    group by r.agent_id,r.module_id,i.collection_revision,i.collection_channel
), import_failures as materialized (
    -- A refused history packet or an older policy revision still belongs to this DC.
    select agent_id,(array_agg(import_failure order by (import_failure->>'at')::timestamptz desc)
        filter(where import_failure is not null))[1] as failure
    from pending where module_id in ('sli.windows.ad-dc','sli.windows.ad-dc-history')
    group by agent_id
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
       coalesce(pending.historical_unimported_packets,0) as historical_unimported_packets,pending.historical_error_at,
       coalesce(failure.failure,pending.import_failure)->>'reason' as import_failure_reason,
       coalesce(failure.failure,pending.import_failure)->>'at' as import_failure_at
from requested wanted
left join import_failures failure on failure.agent_id=wanted.agent_id and wanted.module_id='sli.windows.ad-dc'
left join lateral (
    select r.packet_id,r.received_at,r.collection_read_error
    from sli_agent_stream_receipts r
    where r.agent_id=wanted.agent_id and r.module_id=wanted.module_id
      and r.collection_revision=wanted.revision
      and (r.collection_channel is null)=(wanted.channel is null)
      and coalesce(r.collection_channel,'')=coalesce(wanted.channel,'')
    order by r.received_at desc,r.sequence desc limit 1
) latest on true
left join sli_agent_stream_import_health imported
  on imported.agent_id=wanted.agent_id and imported.module_id=wanted.module_id
 and imported.revision=wanted.revision
 and imported.channel is not distinct from wanted.channel
 and latest.packet_id is not null
left join pending
  on pending.agent_id=wanted.agent_id and pending.module_id=wanted.module_id
 and pending.collection_revision=wanted.revision
 and pending.collection_channel is not distinct from wanted.channel
where not wanted.snapshot
union all
select wanted.agent_id::text,wanted.module_id,wanted.revision,null,
       max(coalesce(c.completed_at,c.created_at)),max(c.published_at),
       min(c.created_at) filter(where c.publication_state='pending'),false,0,null::timestamptz,null::text,null::text
from requested wanted left join sli_agent_snapshot_cycles c
  on c.agent_id=wanted.agent_id and c.module_id=wanted.module_id
 and c.policy->>'policy_revision'=wanted.revision
where wanted.snapshot
group by wanted.agent_id,wanted.module_id,wanted.revision
