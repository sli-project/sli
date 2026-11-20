namespace Sli.Server.Semantic;

internal static class SemanticDispatchRecoverySql
{
    internal const string Claim = """
        with candidate as (
          select job.job_id
          from semantic_correlation_dispatch_jobs job
          join semantic_correlation_rules rule
            on rule.rule_id=job.rule_id and rule.rule_version=job.rule_version
          where job.job_id=any($1::uuid[])
            and job.dispatch_status='queued'
            and job.attempt_count=5 and job.max_attempts=5
            and job.lease_token is null and job.lease_until is null and job.heartbeat_at is null
            and job.available_at<=now()
            and ((job.last_error_code=$2 and position($3 in coalesce(job.last_error_detail,''))>0)
              or (job.last_error_code=$4 and position($5 in coalesce(job.last_error_detail,''))>0))
            and rule.rule_id=$6 and rule.rule_version=$7
            and encode(rule.definition_sha256,'hex')=$8
          order by job.available_at,job.created_at,job.job_id
          for update of job skip locked limit 1
        )
        update semantic_correlation_dispatch_jobs job
        set dispatch_status='leased',lease_token=$9,
            lease_until=now()+(300 * interval '1 second'),heartbeat_at=now(),updated_at=now()
        from candidate where job.job_id=candidate.job_id
        returning job.*
        """;
    internal const string Complete = """
        update semantic_correlation_dispatch_jobs
        set dispatch_status='completed',completed_at=now(),lease_token=null,
            lease_until=null,heartbeat_at=now(),last_error_code=null,
            last_error_detail=null,updated_at=now()
        where job_id=$1 and dispatch_status='leased' and lease_token=$2
        returning job_id
        """;
    internal const string Baseline = """
        select
        (select count(*)::bigint from semantic_security_scenarios
          where evidence_count<>0) as scenario_evidence_nonzero_count,
        (select md5(coalesce(string_agg(scenario_id::text || ':' || evidence_count::text, ',' order by scenario_id),''))
           from semantic_security_scenarios) as scenario_evidence_digest,
        (select count(*)::bigint from semantic_correlation_dispatch_jobs
          where job_id<>all($1::uuid[])) as unrelated_dispatch_count,
        (select md5(coalesce(string_agg(job_id::text || ':' || dispatch_status, ',' order by job_id),''))
           from semantic_correlation_dispatch_jobs where job_id<>all($2::uuid[])) as unrelated_dispatch_digest
        """;
    internal const string Snapshot = """
        select job.job_id::text as job_id,job.dispatch_status,trigger.source_event_id,
               job.partition_key,job.last_error_code,job.last_error_detail,
               job.attempt_count,job.max_attempts,
               job.lease_token,job.lease_until,job.heartbeat_at,
               case when job.lease_until is not null then job.lease_until<=now() else false end as lease_expired,
               rule.rule_id,rule.rule_version,encode(rule.definition_sha256,'hex') as definition_sha256,
               encode(trigger.semantic_sha256,'hex') as source_hash,
               trigger.semantic_contract_version,trigger.normalizer_id,trigger.normalizer_version,
               trigger.normalized_at,
               regexp_replace(job.partition_key, '^.*(?:-|:)', '') as trigger_identity
        from semantic_correlation_dispatch_jobs job
        join normalized_events trigger on trigger.normalized_event_id=job.normalized_event_id
        join semantic_correlation_rules rule on rule.rule_id=job.rule_id and rule.rule_version=job.rule_version
        where job.job_id=any($1::uuid[])
        order by job.job_id
        """;
    internal const string Relations = """
        select $1::bigint as trigger_source_event_id,
               array_agg(distinct normalized.source_event_id order by normalized.source_event_id) as source_event_ids,
               encode(candidate.candidate_key,'hex') as candidate_key_hex,
               count(distinct normalized.source_event_id) filter (where
                 normalized.processing_status='normalized'
                 and normalized.semantic_contract_version=$2
                 and normalized.normalizer_id=$3
                 and normalized.normalizer_version=$4
               ) = count(distinct normalized.source_event_id) as contract_exact,
               bool_and(
                 normalized.processing_status='normalized'
                 and normalized.semantic_contract_version=1
                 and normalized.normalizer_id='windows.named-eventdata'
                 and normalized.normalizer_version='1.3+identity-1.0'
               ) as repairable_contract_exact
        from semantic_correlation_candidates candidate
        join semantic_correlation_candidate_evidence evidence on evidence.candidate_id=candidate.candidate_id
        join normalized_events normalized on normalized.normalized_event_id=evidence.normalized_event_id
        where candidate.rule_id=$5 and candidate.rule_version=$6
        group by candidate.candidate_key
        having bool_or(normalized.source_event_id=$7)
        order by candidate_key_hex
        """;
    internal const string Requeue = """
        update semantic_correlation_dispatch_jobs
        set dispatch_status='queued',available_at=now(),lease_token=null,
            lease_until=null,heartbeat_at=null,updated_at=now()
        where job_id=any($1::uuid[])
          and (
            (
              dispatch_status='quarantined'
              and lease_token is null and lease_until is null
              and attempt_count=max_attempts and attempt_count=5
              and ((heartbeat_at is null and last_error_code=$2)
                or (heartbeat_at is not null and last_error_code=$3))
            )
            or (
              dispatch_status='queued'
              and lease_token is null and lease_until is null and heartbeat_at is null
              and attempt_count=5 and max_attempts=5
            )
            or (
              dispatch_status='leased'
              and lease_token is not null and lease_until<=now() and heartbeat_at is not null
              and attempt_count=5 and max_attempts=5
            )
          )
          and ((last_error_code=$4 and position($5 in coalesce(last_error_detail,''))>0)
            or (last_error_code=$6 and position($7 in coalesce(last_error_detail,''))>0))
        returning job_id
        """;
}
