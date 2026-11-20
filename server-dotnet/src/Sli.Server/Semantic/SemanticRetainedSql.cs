namespace Sli.Server.Semantic;

// Parameterized PostgreSQL queries from the retained-facts reference controller.
internal static class SemanticRetainedSql
{
    internal const string Targets = """
        select core.id
        from semantic_event_rows core
        join storage_v2_channel channel on channel.id=core.channel_id
        join storage_v2_provider provider on provider.id=core.provider_id
        where channel.value='Security'
          and provider.value=$1
          and core.event_id=$2
          and core.id>$3 and core.id<=$4
          and not exists (
              select 1 from normalized_events normalized
              where normalized.source_event_id=core.id
                and normalized.semantic_contract_version=$5
                and normalized.normalizer_id=$6 and normalized.normalizer_version=$7
                and normalized.processing_status='normalized'
                and normalized.source_event_sha256=core.normalized_hash
                and normalized.semantic_type<>'event.unknown'
          )
        order by core.id
        limit $8
        """;
    internal const string Reconcile = """
        select
          count(distinct core.id)::integer as retained_count,
          count(distinct normalized.normalized_event_id) filter (
            where normalized.processing_status='normalized'
              and normalized.source_event_sha256=core.normalized_hash
              and normalized.semantic_type<>'event.unknown'
          )::integer as normalized_count,
          count(distinct normalized.normalized_event_id) filter (
            where normalized.processing_status='failed'
          )::integer as normalization_failed,
          count(distinct normalized.normalized_event_id) filter (
            where normalized.processing_status='quarantined'
          )::integer as normalization_quarantined,
          count(distinct outbox.job_id) filter (where outbox.status='queued')::integer as outbox_queued,
          count(distinct outbox.job_id) filter (where outbox.status='leased')::integer as outbox_leased,
          count(distinct outbox.job_id) filter (where outbox.status='completed')::integer as outbox_completed,
          count(distinct outbox.job_id) filter (where outbox.status='failed')::integer as outbox_failed,
          count(distinct outbox.job_id) filter (where outbox.status='quarantined')::integer as outbox_quarantined,
          count(distinct action_evidence.normalized_event_id)::integer as action_evidence_count
        from semantic_event_rows core
        join storage_v2_channel channel on channel.id=core.channel_id
        join storage_v2_provider provider on provider.id=core.provider_id
        left join normalized_events normalized
          on normalized.source_event_id=core.id
         and normalized.semantic_contract_version=$1
         and normalized.normalizer_id=$2 and normalized.normalizer_version=$3
        left join semantic_processing_outbox outbox
          on outbox.source_event_id=core.id
         and outbox.job_kind in ('normalize_event','semantic_repair')
         and outbox.semantic_contract_version=$4
         and outbox.processor_id=$5 and outbox.processor_version=$6
        left join canonical_action_evidence action_evidence
          on action_evidence.normalized_event_id=normalized.normalized_event_id
        where channel.value='Security' and provider.value=$7 and core.event_id=$8
          and core.id<=$9
        """;
    internal const string ContextReconcile = """
        select
          count(distinct core.id)::integer as retained_count,
          count(distinct normalized.normalized_event_id) filter (
            where normalized.processing_status='normalized'
              and normalized.source_event_sha256=core.normalized_hash
              and normalized.semantic_type<>'event.unknown'
          )::integer as normalized_count,
          count(distinct normalized.normalized_event_id) filter (
            where normalized.processing_status='failed'
          )::integer as normalization_failed,
          count(distinct normalized.normalized_event_id) filter (
            where normalized.processing_status='quarantined'
          )::integer as normalization_quarantined,
          count(distinct outbox.job_id) filter (where outbox.status='queued')::integer as outbox_queued,
          count(distinct outbox.job_id) filter (where outbox.status='leased')::integer as outbox_leased,
          count(distinct outbox.job_id) filter (where outbox.status='completed')::integer as outbox_completed,
          count(distinct outbox.job_id) filter (where outbox.status='failed')::integer as outbox_failed,
          count(distinct outbox.job_id) filter (where outbox.status='quarantined')::integer as outbox_quarantined,
          count(distinct action_evidence.normalized_event_id)::integer as action_evidence_count
        from semantic_event_rows core
        left join normalized_events normalized
          on normalized.source_event_id=core.id
         and normalized.semantic_contract_version=$1
         and normalized.normalizer_id=$2 and normalized.normalizer_version=$3
        left join semantic_processing_outbox outbox
          on outbox.source_event_id=core.id
         and outbox.job_kind in ('normalize_event','semantic_repair')
         and outbox.semantic_contract_version=$4
         and outbox.processor_id=$5 and outbox.processor_version=$6
        left join canonical_action_evidence action_evidence
          on action_evidence.normalized_event_id=normalized.normalized_event_id
        where core.id=any($7)
        """;
    internal const string RepairRows = """
        with selected(source_event_id,source_hash) as (
          select * from unnest($1::bigint[],$2::text[])
        )
        select selected.source_event_id,selected.source_hash,
               original.original_job_count,original.original_job_id,original.original_status,
               original.original_attempt_count,original.original_max_attempts,
               original.original_error_code,original.original_error_detail,
               original.original_source_hash,
               repair.repair_job_count,repair.repair_status,repair.repair_processor_id,
               repair.repair_processor_version,repair.repair_source_hash,
               repair.repair_payload_source_hash,repair.repair_semantic_contract_version,
               repair.repair_original_job_id,repair.repair_history_plan_digest,
               repair.repair_plan_digest,repair.repair_original_attempt_count,
               repair.repair_original_max_attempts,repair.repair_original_error_code,
               repair.repair_original_error_detail_sha256,
               normalized.normalized_current_count,normalized.normalized_proof_count,
               normalized.normalized_proof_hash,normalized.normalized_action_count
        from selected
        left join lateral (
          select count(job.job_id)::integer as original_job_count,
                 min(job.job_id::text) as original_job_id,min(job.status) as original_status,
                 min(job.attempt_count)::integer as original_attempt_count,
                 min(job.max_attempts)::integer as original_max_attempts,
                 min(job.last_error_code) as original_error_code,
                 min(job.last_error_detail) as original_error_detail,
                 min(job.source_identity_json->>'normalized_hash') as original_source_hash
          from public.semantic_processing_outbox job
          where job.source_event_id=selected.source_event_id and job.job_kind='normalize_event'
            and job.semantic_contract_version=$3 and job.processor_id=$4 and job.processor_version=$5
        ) original on true
        left join lateral (
          select count(job.job_id)::integer as repair_job_count,
                 min(job.status) as repair_status,min(job.processor_id) as repair_processor_id,
                 min(job.processor_version) as repair_processor_version,
                 min(job.semantic_contract_version)::integer as repair_semantic_contract_version,
                 min(job.source_identity_json->>'normalized_hash') as repair_source_hash,
                 min(job.payload_json->>'original_source_hash') as repair_payload_source_hash,
                 min(job.payload_json->>'original_job_id') as repair_original_job_id,
                 min(job.payload_json->>'history_plan_digest') as repair_history_plan_digest,
                 min(job.payload_json->>'repair_plan_digest') as repair_plan_digest,
                 min(job.payload_json->>'original_attempt_count') as repair_original_attempt_count,
                 min(job.payload_json->>'original_max_attempts') as repair_original_max_attempts,
                 min(job.payload_json->>'original_error_code') as repair_original_error_code,
                 min(job.payload_json->>'original_error_detail_sha256') as repair_original_error_detail_sha256
          from public.semantic_processing_outbox job
          where job.source_event_id=selected.source_event_id
            and job.job_kind='semantic_v2_quarantine_repair'
        ) repair on true
        left join lateral (
          select count(normalized.normalized_event_id)::integer as normalized_current_count,
                 count(normalized.normalized_event_id) filter (
                   where normalized.processing_status='normalized'
                     and normalized.source_event_sha256=decode(selected.source_hash,'hex')
                     and normalized.semantic_type<>'event.unknown'
                 )::integer as normalized_proof_count,
                 min(encode(normalized.source_event_sha256,'hex')) filter (
                   where normalized.processing_status='normalized'
                     and normalized.source_event_sha256=decode(selected.source_hash,'hex')
                     and normalized.semantic_type<>'event.unknown'
                 ) as normalized_proof_hash,
                 count(distinct action_evidence.canonical_action_id) filter (
                   where normalized.processing_status='normalized'
                     and normalized.source_event_sha256=decode(selected.source_hash,'hex')
                     and normalized.semantic_type<>'event.unknown'
                 )::integer as normalized_action_count
          from public.normalized_events normalized
          left join public.canonical_action_evidence action_evidence
            on action_evidence.normalized_event_id=normalized.normalized_event_id
          where normalized.source_event_id=selected.source_event_id
            and normalized.semantic_contract_version=$6 and normalized.normalizer_id=$7
            and normalized.normalizer_version=$8
        ) normalized on true
        order by selected.source_event_id
        """;
    internal const string PendingRepair = """
        with frozen(event_id,high_watermark) as (
          select * from unnest($1::integer[],$2::bigint[])
        )
        select job.job_id::text as original_job_id,job.source_event_id,
               core.event_id as source_windows_event_id,
               job.source_identity_json->>'normalized_hash' as original_source_hash
        from public.semantic_processing_outbox job
        join semantic_event_rows core on core.id=job.source_event_id
        join frozen on frozen.event_id=core.event_id and core.id<=frozen.high_watermark
        join public.storage_v2_channel channel on channel.id=core.channel_id
        join public.storage_v2_provider provider on provider.id=core.provider_id
        where job.job_kind='normalize_event' and job.status='completed'
          and job.semantic_contract_version=$3
          and job.processor_id=$4 and job.processor_version=$5
          and job.source_identity_json->>'normalized_hash'=encode(core.normalized_hash,'hex')
          and channel.value='Security'
          and provider.value=case core.event_id
            when 1102 then 'Microsoft-Windows-Eventlog'
            else 'Microsoft-Windows-Security-Auditing' end
          and not exists (
            select 1 from public.normalized_events normalized
            where normalized.source_event_id=core.id
              and normalized.semantic_contract_version=$6
              and normalized.normalizer_id=$7 and normalized.normalizer_version=$8
              and normalized.processing_status='normalized'
              and normalized.source_event_sha256=core.normalized_hash
              and normalized.semantic_type<>'event.unknown'
          )
        order by job.source_event_id,job.job_id
        """;
    internal const string ExactQueue = """
        select job.source_event_id,job.status,
               (job.source_identity_json->>'id'=core.id::text
                and job.source_identity_json->>'normalized_hash'=encode(core.normalized_hash,'hex')) as identity_matches,
               exists (
                   select 1 from public.normalized_events normalized
                   where normalized.source_event_id=core.id
                     and normalized.semantic_contract_version=$1
                     and normalized.normalizer_id=$2 and normalized.normalizer_version=$3
                     and normalized.processing_status='normalized'
                     and normalized.source_event_sha256=core.normalized_hash
               ) as normalized
        from public.semantic_processing_outbox job
        left join semantic_event_rows core on core.id=job.source_event_id
        where job.source_event_id=any($4) and job.job_kind='normalize_event'
          and job.semantic_contract_version=$5
          and job.processor_id=$6 and job.processor_version=$7
        """;
}
