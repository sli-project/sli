begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_semantic_worker_v50'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 050 rollback requires membership in adlog_storage_owner';
    end if;
end
$$;

revoke all privileges on table
    runtime_worker_heartbeats
from adlog_semantic_worker;

set local role adlog_storage_owner;

revoke all privileges on table
    events_v2_core,
    storage_v2_provider,
    storage_v2_channel,
    storage_v2_computer,
    storage_v2_archive_sets,
    storage_v2_archive_blocks,
    semantic_processing_outbox,
    normalized_events,
    canonical_actions,
    canonical_action_evidence,
    canonical_action_state_evidence,
    semantic_correlation_rules,
    semantic_correlation_candidates,
    semantic_correlation_candidate_evidence,
    semantic_correlation_replays,
    semantic_correlation_subscriptions,
    semantic_correlation_dispatch_jobs,
    semantic_security_scenarios,
    semantic_scenario_steps,
    semantic_scenario_evidence,
    semantic_risk_contributions,
    semantic_scenario_coverage_history,
    semantic_risk_policies,
    semantic_risk_policy_subscriptions,
    semantic_control_health_observations,
    semantic_risk_evaluation_jobs,
    semantic_risk_evaluation_results
from adlog_semantic_worker;

revoke usage on schema public from adlog_semantic_worker;

delete from schema_migrations
where version=50 and name='semantic_worker_least_privilege';

commit;
