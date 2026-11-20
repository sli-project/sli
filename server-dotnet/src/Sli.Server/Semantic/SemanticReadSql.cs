namespace Sli.Server.Semantic;
internal static class SemanticReadSql
{
    internal const string job_rows = """
        select evaluation_mode,evaluation_status,count(*) as job_count,
                       coalesce(sum(attempt_count),0) as attempts,
                       count(*) filter (where last_error_code is not null) as errors,
                       min(created_at) as first_created_at,max(updated_at) as last_updated_at
                from semantic_risk_evaluation_jobs
                where created_at >= now() - ($1 * interval '1 hour')
                group by evaluation_mode,evaluation_status
                order by evaluation_mode,evaluation_status
        """;
    internal const string result_rows = """
        select evaluation_mode,risk_class,confidence,coverage_status,
                       count(*) as result_count,count(scenario_id) as scenario_count,
                       round(avg(display_score),2) as average_risk_score,
                       round(avg(confidence_score),2) as average_confidence_score,
                       round(avg(evaluation_ms),2) as average_evaluation_ms,
                       max(evaluation_ms) as max_evaluation_ms
                from semantic_risk_evaluation_results
                where created_at >= now() - ($1 * interval '1 hour')
                group by evaluation_mode,risk_class,confidence,coverage_status
                order by evaluation_mode,risk_class,confidence,coverage_status
        """;
    internal const string policy_rows = """
        select lifecycle_status,source_kind,count(*) as policy_count
                from semantic_risk_policies
                group by lifecycle_status,source_kind
                order by lifecycle_status,source_kind
        """;
    internal const string control_rows = """
        select coverage_status,count(*) as item_count
                from semantic_control_health_observations
                where created_at >= now() - ($1 * interval '1 hour')
                group by coverage_status order by coverage_status
        """;
    internal const string coverage_rows = """
        select coverage_status,count(*) as item_count
                from semantic_risk_evaluation_results
                where created_at >= now() - ($1 * interval '1 hour')
                group by coverage_status order by coverage_status
        """;
    internal const string quality_rows = """
        select count(*) as normalized,
                       count(*) filter (where coalesce((quality_json->>'missing_actor_sid')::boolean,false)) as missing_actor_sid,
                       count(*) filter (where coalesce((quality_json->>'unresolved_actor')::boolean,false)) as unresolved_actor,
                       count(*) filter (where coalesce((quality_json->>'unresolved_target')::boolean,false)) as unresolved_target,
                       count(*) filter (where coalesce((quality_json->>'missing_source_ip')::boolean,false)) as missing_source_ip,
                       count(*) filter (where coalesce((quality_json->>'unknown_event_mapping')::boolean,false)) as unknown_event_mapping,
                       count(*) filter (where occurred_at_utc > source_ingested_at + interval '5 minutes') as future_clock_skew,
                       count(*) filter (where source_ingested_at > occurred_at_utc + interval '15 minutes') as delayed_ingest,
                       round(avg(greatest(0,extract(epoch from (source_ingested_at-occurred_at_utc)))),2) as average_ingest_delay_seconds,
                       round(max(greatest(0,extract(epoch from (source_ingested_at-occurred_at_utc)))),2) as max_ingest_delay_seconds
                from normalized_events
                where normalized_at >= now() - ($1 * interval '1 hour')
        """;
    internal const string review_rows = """
        with latest as (
                    select distinct on (scenario_id) scenario_id,verdict,reviewed_at
                    from semantic_scenario_reviews
                    order by scenario_id,reviewed_at desc,review_id desc
                )
                select verdict,count(*) as item_count
                from latest
                where reviewed_at >= now() - ($1 * interval '1 hour')
                group by verdict order by verdict
        """;
    internal const string Integrity_state_rows = """
        with latest as (
                    select distinct on (server,channel) server,channel,status
                    from collector_channel_runs
                    order by server,channel,created_at desc,id desc
                )
                select c.server_hostname,c.channel,c.last_successful_collection_utc,
                       c.backfill_completed,l.status as last_status
                from collection_channel_state c
                left join latest l on l.server=c.server_hostname and l.channel=c.channel
                order by c.server_hostname,c.channel
                limit 100
        """;
    internal const string Integrity_run_rows = """
        select count(*) as runs,
                       count(*) filter (where status in ('failed','error','timeout','partial_timeout')) as noncomplete_runs,
                       coalesce(sum(inserted),0) as inserted,
                       coalesce(sum(skipped),0) as skipped
                from collector_channel_runs
                where created_at >= now() - ($1 * interval '1 hour')
        """;
    internal const string Integrity_audit_rows = """
        select count(*) as audits,
                       count(*) filter (where decision='rejected' and reason='record_id_rollback_detected') as rejected_rollbacks,
                       count(*) filter (
                           where decision='rejected' and reason='record_id_rollback_detected'
                             and collection_status='completed'
                             and import_inserted=0 and import_skipped=0
                             and new_record_id=old_record_id
                       ) as stale_empty_proposals,
                       count(*) filter (
                           where decision='rejected' and reason='record_id_rollback_detected'
                             and not (
                                 collection_status='completed'
                                 and import_inserted=0 and import_skipped=0
                                 and new_record_id=old_record_id
                             )
                       ) as actionable_rollbacks,
                       count(*) filter (where decision='no_change') as no_change,
                       count(*) filter (where decision='committed') as committed
                from collector_cursor_audit
                where created_at >= now() - ($1 * interval '1 hour')
        """;
}
