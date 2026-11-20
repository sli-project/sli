-- A core-pinned delivery is retained work, not an outstanding legacy drain.
begin;
select pg_advisory_xact_lock(hashtext('sli_plugin_core_drain_handoff_v168'));
select pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_runtime_v76'));

do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 168 requires membership in adlog_storage_owner';
    end if;
    if exists(select 1 from public.schema_migrations where version=168) then
        raise exception 'migration 168 already recorded';
    end if;
    if not exists(select 1 from public.schema_migrations where version=167 and name='agent_updates')
       or exists(select 1 from public.schema_migrations where version>167) then
        raise exception 'migration 168 requires exact migration 167 agent_updates';
    end if;
end $$;

-- Keep the existing aggregate-only lifecycle boundary and its owner/ACL.
-- Only unclaimed work pinned to a live, exactly bound core consumer may wait
-- across disable/re-enable. Active delivery/component leases still drain.
grant usage on schema sli_jobs to adlog_storage_owner;
grant select(spec,plugin_id,source_instance_id,state,lease_until,deadline_at)
    on sli_jobs.jobs to adlog_storage_owner;
create or replace function public.read_plugin_runtime_queue_nonterminal_v1()
returns bigint language sql stable security definer set search_path=pg_catalog,public
as $$
    select count(*)::bigint from public.acquisition_delivery_outbox delivery
    join public.acquisition_consumer_subscriptions subscription
      on subscription.subscription_id=delivery.subscription_id
    where subscription.consumer_id='sli.windows.vpn-radius'
      and subscription.consumer_component_id='radius-session-observation'
      and delivery.delivery_state in ('queued','leased','failed','quarantined')
      and not (
          delivery.delivery_state in ('queued','failed')
          and exists(
              select 1 from sli_jobs.jobs job
              where job.plugin_id='sli.remote-access'
                and job.source_instance_id=subscription.source_instance_id
                and job.spec->>'handler_id'='radius-session-observation'
                and job.spec->'pinned_input'->>'subscription_id'=subscription.subscription_id
                and job.state='leased'
                and job.lease_until>clock_timestamp()
                and job.deadline_at>clock_timestamp()
                and job.spec->'pinned_input'->'delivery_ids' @> jsonb_build_array(delivery.delivery_id)
          )
      )
$$;

insert into public.schema_migrations(version,name) values(168,'plugin_core_drain_handoff');
commit;
