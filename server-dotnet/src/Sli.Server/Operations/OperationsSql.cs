// SQL copied from the frozen read-only Operations providers.
namespace Sli.Server.Operations;

internal static class OperationsSql
{
    internal const string Agents = """
select a.id::text, a.host_id::text, a.instance_name, a.status, a.last_seen,
       a.created_at, a.assigned_modules, a.collection_policy, a.registration_host_name,
       a.policy_revision, a.applied_policy_revision, a.applied_collection_state, a.windows_audit,
       dc.id as server_id,dc.hostname as canonical_host_name,a.rights_probe ? 'identity_conflict' as identity_conflict,
       coalesce(a.rights_probe->>'agent_version',version.version,issued_version.details->>'agent_version') as agent_version,
       retired.details->>'replaced_by' as replaced_by,
       (select coalesce(jsonb_agg(jsonb_build_object('module_id',b.module_id,'source_name',b.source_name)), '[]'::jsonb)
        from sli_agent_module_bindings b where b.agent_id=a.id) as source_bindings,
       ack.occurred_at as policy_applied_at, enrolled.fqdn as domain, enrolled.host_name,
       gap.occurred_at as last_accepted_gap_at, a.packet_expiry,
       (select received_at from sli_agent_receipts where agent_id=a.id
        order by received_at desc limit 1) as last_packet_at
from sli_agents a
left join lateral (
    select b.source_name from sli_agent_module_bindings b where b.agent_id=a.id and b.module_id='sli.windows.ad-dc'
) binding on true
left join lateral (
    select min(s.id) as id,min(s.hostname) as hostname from servers s
    where s.role='domain_controller' and s.is_active and binding.source_name is not null and coalesce(
        s.id::text=(select details->>'server_id' from sli_agent_audit where target=a.id::text and action='issue' order by id desc limit 1), (
        lower(coalesce(binding.source_name,a.registration_host_name)) in (lower(s.hostname),lower(s.fqdn))
        or strpos(coalesce(binding.source_name,a.registration_host_name),'.')=0
            and lower(coalesce(binding.source_name,a.registration_host_name))=split_part(lower(coalesce(nullif(s.fqdn,''),s.hostname)),'.',1)
        or strpos(coalesce(nullif(s.fqdn,''),s.hostname),'.')=0
            and lower(s.hostname)=split_part(lower(coalesce(binding.source_name,a.registration_host_name)),'.',1)))
    having count(*)=1
) dc on true
left join lateral (select details from sli_agent_audit where target=a.id::text and action='disable'
    and details->>'reason'='registration_replaced' order by id desc limit 1) retired on true
left join lateral (select details from sli_agent_audit where target=a.id::text and action='issue' order by id desc limit 1) issued_version on true
left join lateral (select version from sli_agent_update_results where agent_id=a.id order by observed_at desc limit 1) version on true
left join lateral (
    select occurred_at from sli_agent_audit
    where target=a.id::text and action='sequence_gap_accepted'
    order by id desc limit 1
) gap on true
left join lateral (
    select occurred_at from sli_agent_audit
    where target=a.id::text and action='policy_ack'
      and details->>'revision'=a.policy_revision::text
    order by id desc limit 1
) ack on true
left join lateral (
    select d.fqdn, coalesce(nullif(btrim(v.attributes_json->'attributes'->>'dns_host_name'),''),
                           nullif(btrim(v.attributes_json->'attributes'->>'display_name'),'')) as host_name
    from sli_agent_audit issued
    join sli_agent_group_approval_links c on issued.actor='enrollment:' || c.enrollment_token_id::text
    join sli_agent_group_requests r on r.id=c.request_id
    join ad_context_entity_versions v on v.id=r.computer_version_id
    join sli_agent_group_tokens t on t.id=r.token_id
    join domains d on d.id=t.domain_id
    where issued.target=a.id::text and issued.action='issue'
    order by issued.id desc limit 1
) enrolled on true
order by a.created_at, a.id
""";

    internal const string Streams = """
with requested as materialized (
    select * from jsonb_to_recordset(@requested::jsonb) as x(
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
    where i.imported_at is null and i.module_disabled_at is null
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
""";

    internal const string Queues = """
select 'processing' as queue_name,status as queue_status,
                       count(*) as depth,
                       coalesce(sum(greatest(attempt_count-1,0)),0) as retries,
                       count(*) filter (
                           where status='leased' and lease_until<now()
                       ) as expired_leases,
                       coalesce(max(extract(epoch from (now()-created_at)))
                           filter (where status in ('queued','failed')),0)
                           ::bigint as oldest_ready_age_seconds,
                       greatest(0, coalesce(max(extract(epoch from (now()-created_at)))
                           filter (where status in ('queued','failed','leased')),0))
                           ::bigint as oldest_pending_age_seconds,
                       count(*) filter (where status='completed'
                           and completed_at>=now()-interval '1 hour'
                           and completed_at<=now()) as completed_last_hour
                from semantic_processing_outbox
                group by status
                union all
                select 'dispatch',dispatch_status,count(*),
                       coalesce(sum(greatest(attempt_count-1,0)),0),
                       count(*) filter (
                           where dispatch_status='leased' and lease_until<now()
                       ),
                       coalesce(max(extract(epoch from (now()-created_at)))
                           filter (where dispatch_status in ('queued','failed')),0)
                           ::bigint,
                       greatest(0, coalesce(max(extract(epoch from (now()-created_at)))
                           filter (where dispatch_status in ('queued','failed','leased')),0))::bigint,
                       count(*) filter (where dispatch_status='completed'
                           and completed_at>=now()-interval '1 hour'
                           and completed_at<=now())
                from semantic_correlation_dispatch_jobs
                group by dispatch_status
                union all
                select 'risk',evaluation_status,count(*),
                       coalesce(sum(greatest(attempt_count-1,0)),0),
                       count(*) filter (
                           where evaluation_status='leased' and lease_until<now()
                       ),
                       coalesce(max(extract(epoch from (now()-created_at)))
                           filter (where evaluation_status in ('queued','failed')),0)
                           ::bigint,
                       greatest(0, coalesce(max(extract(epoch from (now()-created_at)))
                           filter (where evaluation_status in ('queued','failed','leased')),0))::bigint,
                       count(*) filter (where evaluation_status='completed'
                           and completed_at>=now()-interval '1 hour'
                           and completed_at<=now())
                from semantic_risk_evaluation_jobs
                group by evaluation_status
                order by queue_name,queue_status
""";

    internal const string CollectorState = """
select
            c.server_hostname,
            c.channel,
            c.archive_start_utc,
            c.last_collection_start_utc,
            c.last_successful_collection_utc,
            c.last_event_time_utc,
            c.last_event_record_id,
            c.backfill_completed,
            c.updated_at,
            coalesce(run_totals.event_count, 0) as event_count,
            c.last_event_time_utc as latest_event_time_utc,
            c.last_event_record_id as latest_event_record_id,
            a.current_limit,
            a.recovery_mode,
            a.last_action,
            a.last_status as adaptive_last_status,
            a.last_lag_minutes
        from collection_channel_state c
        left join (
            select server, channel, sum(coalesce(inserted, 0)) as event_count
            from collector_channel_runs
            group by server, channel
        ) run_totals on run_totals.server = c.server_hostname and run_totals.channel = c.channel
        left join collector_adaptive_state a on a.server = c.server_hostname and a.channel = c.channel
        order by c.server_hostname, case c.channel
            when 'Security' then 1
            when 'System' then 2
            when 'Directory Service' then 3
            when 'Microsoft-Windows-PowerShell/Operational' then 4
            when 'Microsoft-Windows-TaskScheduler/Operational' then 5
            when 'DNS Server' then 6
            else 99 end, c.channel
""";

    internal const string CollectorHistory = """
with recent as (
            select *
            from collector_channel_runs
            where coalesce(finished_utc, created_at::text) >= @cutoff
        ),
        aggregate_24h as (
            select
                server,
                channel,
                sum(case when status in ('timeout', 'partial_timeout') then 1 else 0 end) as timeouts_24h,
                sum(case when status = 'partial_timeout' then 1 else 0 end) as partial_timeouts_24h,
                sum(coalesce(inserted, 0)) as inserted,
                sum(coalesce(skipped, 0)) as skipped,
                max(coalesce(partial_count, 0)) as last_partial_count
            from recent
            group by server, channel
        ),
        latest as (
            select distinct on (server, channel)
                server, channel, status as last_status,
                query_duration_ms, import_duration_ms, import_queue_wait_ms, import_retry_count,
                total_duration_ms, events_per_second, last_record_id_delta, lag_delta_minutes,
                collection_mode, requested_collection_mode, cursor_strategy, cursor_fallback_reason,
                collector_backend, backend_reason
            from collector_channel_runs
            order by server, channel, coalesce(finished_utc, created_at::text) desc, id desc
        )
        select
            coalesce(a.server, l.server) as server,
            coalesce(a.channel, l.channel) as channel,
            coalesce(a.timeouts_24h, 0) as timeouts_24h,
            coalesce(a.partial_timeouts_24h, 0) as partial_timeouts_24h,
            coalesce(a.inserted, 0) as inserted,
            coalesce(a.skipped, 0) as skipped,
            coalesce(a.last_partial_count, 0) as last_partial_count,
            l.last_status, l.query_duration_ms, l.import_duration_ms, l.import_queue_wait_ms,
            l.import_retry_count, l.total_duration_ms, l.events_per_second, l.last_record_id_delta,
            l.lag_delta_minutes, l.collection_mode, l.requested_collection_mode, l.cursor_strategy,
            l.cursor_fallback_reason, l.collector_backend, l.backend_reason
        from aggregate_24h a
        full outer join latest l on l.server = a.server and l.channel = a.channel
""";

    internal const string Sources = """
select
            s.hostname,
            s.fqdn,
            s.role,
            s.is_active,
            s.os_name,
            s.os_version,
            d.fqdn as domain_fqdn,
            d.netbios_name,
            si.name as site_name
        from servers s
        join domains d on d.id = s.domain_id
        left join sites si on si.id = s.site_id
        order by s.hostname
""";

    internal const string SourceInventory = """
select
                domain.fqdn as domain_fqdn,
                lower(coalesce(version.attributes_json->'attributes'->>'display_name','')) as display_key,
                lower(trim(trailing '$' from coalesce(version.attributes_json->'attributes'->>'sam_account_name',''))) as sam_key,
                lower(split_part(coalesce(version.attributes_json->'attributes'->>'dns_host_name',''),'.',1)) as dns_key,
                version.attributes_json->'attributes'->>'dns_host_name' as fqdn,
                version.attributes_json->'attributes'->>'operating_system' as os_name,
                version.attributes_json->'attributes'->>'operating_system_version' as os_version,
                version.attributes_json->'attributes'->'ip_addresses' as ip_addresses,
                version.attributes_json->'attributes'->'logical_disks' as logical_disks,
                version.attributes_json->'attributes'->>'technical_inventory_status' as technical_inventory_status,
                version.attributes_json->'attributes'->>'technical_inventory_observed_at_utc' as technical_inventory_observed_at_utc,
                version.last_observed_at_utc
            from ad_context_entity_versions version
            join ad_context_runs run on run.run_id = version.source_run_id
            join domains domain on domain.id = run.domain_id
            where version.valid_to_utc is null
              and version.source_section='directory_accounts'
              and lower(coalesce(version.attributes_json->'identity'->>'kind',''))='ad_computer'
              and (
                    lower(coalesce(version.attributes_json->'attributes'->>'display_name','')) = any(@hostnames)
                 or lower(trim(trailing '$' from coalesce(version.attributes_json->'attributes'->>'sam_account_name',''))) = any(@hostnames)
                 or lower(split_part(coalesce(version.attributes_json->'attributes'->>'dns_host_name',''),'.',1)) = any(@hostnames)
                 or lower(rtrim(coalesce(version.attributes_json->'attributes'->>'dns_host_name',''),'.')) = any(@hostnames)
              )
            order by version.last_observed_at_utc desc
            limit @limit
""";

    internal const string Outbox = """
select effective_state as state, count(*) as batches,
                       coalesce(sum(event_count), 0) as events
                from (
                    select event_count, case
                        when state = 'completed' then 'completed'
                        when state = 'quarantined' then 'quarantined'
                        when state = 'leased' and lease_until > now() then 'leased'
                        when state = 'leased' then 'expired_lease'
                        when state in ('pending', 'failed') and available_at <= now() then 'ready'
                        when state in ('pending', 'failed') then 'delayed'
                        else state end as effective_state
                    from storage_v2_outbox
                ) classified group by effective_state
""";

    internal const string ChannelCycles = """
select
                    concat('collector-job-', coalesce(job_id::text, 'unknown'), '-', server, '-',
                           extract(epoch from created_at)::bigint) as run_id,
                    concat('collector-', server) as worker_id,
                    job_id, server,
                    min(started_utc::timestamptz) as started_at,
                    max(finished_utc::timestamptz) as finished_at,
                    greatest(0, (extract(epoch from (
                        max(finished_utc::timestamptz) - min(started_utc::timestamptz)
                    )) * 1000)::bigint) as duration_ms,
                    case
                        when bool_and(status in ('failed', 'timeout', 'error')) then 'failed'
                        when bool_or(status in ('failed', 'timeout', 'error', 'partial', 'partial_timeout')) then 'partial'
                        else 'completed'
                    end as status,
                    array_agg(channel order by channel) as channels_json,
                    sum(coalesce(inserted, 0)) as inserted,
                    sum(coalesce(skipped, 0)) as skipped,
                    max(limit_used) as max_events_per_channel,
                    array_remove(array_agg(nullif(error, '')), null) as errors_json,
                    created_at
                from collector_channel_runs
                where created_at >= now() - interval '24 hours'
                group by job_id, server, created_at
                order by max(finished_utc::timestamptz) desc nulls last
                limit @limit
""";
}
