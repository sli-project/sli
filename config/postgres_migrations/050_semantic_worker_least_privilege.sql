-- Stage 8 source-only grant set for the dormant semantic worker.
-- The role is NOLOGIN and receives no collection, schema, finding or survey rights.
begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_semantic_worker_v50'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 050 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=49 and name='event_noise_browse_index'
    ) then
        raise exception 'migration 050 requires schema migration 049';
    end if;
    if to_regrole('adlog_semantic_worker') is null then
        raise exception 'migration 050 requires NOLOGIN role adlog_semantic_worker';
    end if;
end
$$;

-- Runtime heartbeat ownership predates the storage-owner boundary on the
-- production database.  The migration session is its owner (or superuser);
-- granting this narrow surface after SET ROLE would fail on that topology.
grant select,insert,update on table
    runtime_worker_heartbeats
to adlog_semantic_worker;

set local role adlog_storage_owner;

grant usage on schema public to adlog_semantic_worker;

grant select on table
    events_v2_core,
    storage_v2_provider,
    storage_v2_channel,
    storage_v2_computer,
    storage_v2_archive_sets,
    storage_v2_archive_blocks
to adlog_semantic_worker;

grant select,insert,update on table
    semantic_processing_outbox,
    normalized_events,
    canonical_actions,
    canonical_action_evidence,
    canonical_action_state_evidence,
    semantic_correlation_candidates,
    semantic_correlation_candidate_evidence,
    semantic_correlation_replays,
    semantic_correlation_dispatch_jobs,
    semantic_security_scenarios,
    semantic_risk_policies,
    semantic_risk_evaluation_jobs
to adlog_semantic_worker;

grant select,insert on table
    semantic_scenario_steps,
    semantic_scenario_evidence,
    semantic_risk_contributions,
    semantic_scenario_coverage_history
to adlog_semantic_worker;

grant select on table
    semantic_correlation_rules,
    semantic_correlation_subscriptions,
    semantic_risk_policy_subscriptions
to adlog_semantic_worker;

grant select,insert on table
    semantic_control_health_observations,
    semantic_risk_evaluation_results
to adlog_semantic_worker;

insert into schema_migrations(version,name)
values (50,'semantic_worker_least_privilege')
on conflict(version) do update set name=excluded.name;

commit;
