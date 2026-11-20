namespace Sli.Server.Semantic;

// Exact PostgreSQL selectors from semantic_investigation_backfill and its split modules.
internal static class SemanticInvestigationSql
{
    internal const string HistoryTargets = """
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
    internal const string ContextCandidates = """
        select login.id as source_event_id,
               encode(login.normalized_hash,'hex') as normalized_hash,
               login.target_user_sid as login_target_user_sid,
               reset_event.target_user_sid as reset_target_user_sid,
               reset_keywords.value as reset_keywords
        from semantic_event_rows login
        join storage_v2_channel login_channel
          on login_channel.id=login.channel_id and login_channel.value=$1
        join storage_v2_provider login_provider
          on login_provider.id=login.provider_id and login_provider.value=$2
        join semantic_event_rows reset_event
          on reset_event.domain_id=login.domain_id
         and lower(nullif(btrim(reset_event.target_user_sid),''))=
             lower(nullif(btrim(login.target_user_sid),''))
         and reset_event.event_id=any($3) and reset_event.id<=$4
         and login.time_created_utc>reset_event.time_created_utc
         and login.time_created_utc<=reset_event.time_created_utc+interval '1 hour'
        join storage_v2_channel reset_channel
          on reset_channel.id=reset_event.channel_id and reset_channel.value=$5
        join storage_v2_provider reset_provider
          on reset_provider.id=reset_event.provider_id and reset_provider.value=$6
        left join storage_v2_keywords reset_keywords
          on reset_keywords.id=reset_event.keywords_id
        where login.event_id=4624 and login.id>$7 and login.id<=$8
          {normalized_clause}
        order by login.id,reset_event.time_created_utc,reset_event.id
        """;
    internal const string ContextAggregate = """
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
    internal const string FactAnchors = """
        select id
        from semantic_event_rows
        where id>$1 and id<=$2 and event_id=any($3)
        order by id
        limit $4
        """;
    internal const string FactContext = """
        select distinct login.id
        from semantic_event_rows login
        join semantic_event_rows reset_event
          on reset_event.domain_id=login.domain_id
         and lower(nullif(btrim(reset_event.target_user_sid),''))=
             lower(nullif(btrim(login.target_user_sid),''))
        join normalized_events reset
          on reset.source_event_id=reset_event.id
         and reset.processing_status='normalized'
         and reset.semantic_contract_version=$1
         and reset.normalizer_id=$2 and reset.normalizer_version=$3
         and reset.semantic_type='account.password.reset.succeeded'
         and reset.quality_json->'relation_account_identity'->>'state'='exact'
         and reset_event.event_id=$4
        where login.id>$5 and login.id<=$6
          and login.event_id=any($7)
          and nullif(btrim(login.target_user_sid),'') is not null
          and login.time_created_utc>reset.occurred_at_utc
          and login.time_created_utc<=reset.occurred_at_utc+interval '1 hour'
        order by login.id
        limit $8
        """;
    internal const string RelationTargets = """
        select normalized_events.normalized_event_id,normalized_events.source_event_id
        from normalized_events
        join unnest($1::text[],$2::integer[]) as source_contract(semantic_type,event_id)
          on source_contract.semantic_type=normalized_events.semantic_type
        join semantic_event_rows source_event
          on source_event.id=normalized_events.source_event_id
         and source_event.event_id=source_contract.event_id
        where normalized_events.processing_status='normalized'
          and normalized_events.semantic_contract_version=$3
          and normalized_events.normalizer_id=$4 and normalized_events.normalizer_version=$5
          and normalized_events.normalized_at<=$6
          and normalized_events.source_event_id>$7 and normalized_events.source_event_id<=$8
          and normalized_events.semantic_type=any($9)
          and (
            normalized_events.semantic_type<>'authentication.session.created'
            or exists (
              select 1
              from normalized_events reset
              join semantic_event_rows reset_source_event
                on reset_source_event.id=reset.source_event_id
               and reset_source_event.event_id=$10
              where reset.processing_status='normalized'
                and reset.semantic_contract_version=$11
                and reset.normalizer_id=$12 and reset.normalizer_version=$13
                and reset.normalized_at<=$14
                and reset.semantic_type='account.password.reset.succeeded'
                and reset.quality_json->'relation_account_identity'->>'state'='exact'
                and reset.facts_json->>'domain_id'=normalized_events.facts_json->>'domain_id'
                and reset.facts_json->>'relation_account_sid'=normalized_events.facts_json->>'relation_account_sid'
                and normalized_events.occurred_at_utc>reset.occurred_at_utc
                and normalized_events.occurred_at_utc<=reset.occurred_at_utc+interval '1 hour'
            )
          )
        order by normalized_events.source_event_id,normalized_events.normalized_event_id
        limit $15
        """;
    internal const string RecoveryCandidates = """
        select job.job_id::text as job_id,
               job.normalized_event_id::text as normalized_event_id,
               normalized.source_event_id,normalized.normalized_at,
               rule.rule_id,rule.rule_version,
               encode(rule.definition_sha256,'hex') as definition_sha256,
               job.dispatch_status,job.attempt_count,job.max_attempts,
               job.last_error_code,job.last_error_detail
        from semantic_correlation_dispatch_jobs job
        join normalized_events normalized
          on normalized.normalized_event_id=job.normalized_event_id
        join semantic_correlation_rules rule
          on rule.rule_id=job.rule_id and rule.rule_version=job.rule_version
        where job.dispatch_status='quarantined'
          and job.attempt_count>=job.max_attempts
          and job.completed_at is null
          and job.last_error_code=$1
          and job.last_error_detail ilike $2
          and normalized.normalized_at<=$3
          and normalized.source_event_id<=$4
          and rule.lifecycle_status='shadow'
          and ({exact_rules})
          {job_filter}
        order by job.job_id
        limit $5
        {lock_clause}
        """;
    internal const string Recover = """
        update semantic_correlation_dispatch_jobs
        set dispatch_status='failed',attempt_count=max_attempts-1,
            available_at=now(),lease_token=null,lease_until=null,
            heartbeat_at=null,completed_at=null,updated_at=now()
        where job_id=any($1::uuid[])
          and dispatch_status='quarantined'
          and attempt_count>=max_attempts
          and last_error_code=$2
          and last_error_detail ilike $3
        returning job_id::text as job_id
        """;
    internal const string FactsCompletion = """
        select requested.source_event_id,
               fact.processing_status,
               job.status as outbox_status
        from unnest($1::bigint[]) requested(source_event_id)
        left join normalized_events fact
          on fact.source_event_id=requested.source_event_id
         and fact.semantic_contract_version=$2
         and fact.normalizer_id=$3
         and fact.normalizer_version=$4
        left join semantic_processing_outbox job
          on job.source_event_id=requested.source_event_id
         and job.job_kind='normalize_event'
         and job.semantic_contract_version=$5
         and job.processor_id=$6
         and job.processor_version=$7
        order by requested.source_event_id
        """;
}
