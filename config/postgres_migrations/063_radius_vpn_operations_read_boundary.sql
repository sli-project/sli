-- Stage 9 aggregate-only Operations boundary for the VPN/RADIUS pilot.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_radius_vpn_operations_v63')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 063 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=62 and name='vpn_session_report_read_boundary'
    ) then
        raise exception 'migration 063 requires schema migration 062';
    end if;
    if to_regrole('adlog_vpn_session_reader_owner') is null then
        raise exception 'migration 063 requires VPN session reader owner';
    end if;
    if to_regclass('radius_vpn_operations_v1') is not null then
        raise exception 'migration 063 requires absent operations view';
    end if;
end
$$;

set local role adlog_storage_owner;

grant select(
    display_name,desired_activation,observed_health,updated_at
) on acquisition_source_instances
to adlog_vpn_session_reader_owner;
grant select(
    stream_id,transport_binding,consumer_id,authority_mode,
    replay_policy,resource_profile_id,desired_activation
) on acquisition_consumer_subscriptions
to adlog_vpn_session_reader_owner;
grant select(
    source_instance_id,stream_id,transport_binding,revision,updated_at
) on acquisition_stream_cursors
to adlog_vpn_session_reader_owner;

reset role;

grant select(id,capability_key) on access_capabilities
to adlog_vpn_session_reader_owner;
grant select(capability_id) on access_capability_assignments
to adlog_vpn_session_reader_owner;
grant select(capability_id) on access_package_capabilities
to adlog_vpn_session_reader_owner;
grant select(report_key,status,version) on report_registry_v4
to adlog_vpn_session_reader_owner;
grant usage,create on schema public
to adlog_vpn_session_reader_owner;

set local role adlog_vpn_session_reader_owner;

create view radius_vpn_operations_v1
with (security_barrier=true)
as
select
    source.source_instance_id,
    source.display_name as source_display_name,
    domain_row.id as domain_id,
    source.desired_activation as source_activation,
    source.observed_health as source_health,
    source.updated_at as source_updated_at,
    subscription.subscription_id,
    subscription.desired_activation as subscription_activation,
    subscription.authority_mode,
    subscription.replay_policy,
    subscription.resource_profile_id,
    cursor_row.revision as cursor_revision,
    cursor_row.updated_at as cursor_updated_at,
    coalesce(coverage.total_delivery_count,0)::bigint
        as total_delivery_count,
    coalesce(coverage.queued_delivery_count,0)::bigint
        as queued_delivery_count,
    coalesce(coverage.leased_delivery_count,0)::bigint
        as leased_delivery_count,
    coalesce(coverage.failed_delivery_count,0)::bigint
        as failed_delivery_count,
    coalesce(coverage.delivered_delivery_count,0)::bigint
        as delivered_delivery_count,
    coalesce(coverage.quarantined_delivery_count,0)::bigint
        as quarantined_delivery_count,
    coalesce(coverage.projected_receipt_count,0)::bigint
        as projected_receipt_count,
    coalesce(coverage.identity_unresolved_count,0)::bigint
        as identity_unresolved_count,
    coalesce(coverage.timestamp_unresolved_count,0)::bigint
        as timestamp_unresolved_count,
    coalesce(coverage.projected_session_count,0)::bigint
        as projected_session_count,
    (
      select count(*)
      from access_capabilities capability
      where capability.capability_key in (
        'vpn.sessions.view','vpn.session.evidence.read'
      )
    )::bigint as registered_capability_count,
    (
      select count(*)
      from access_capability_assignments assignment
      join access_capabilities capability
        on capability.id=assignment.capability_id
      where capability.capability_key in (
        'vpn.sessions.view','vpn.session.evidence.read'
      )
    )::bigint as direct_capability_assignment_count,
    (
      select count(*)
      from access_package_capabilities package_capability
      join access_capabilities capability
        on capability.id=package_capability.capability_id
      where capability.capability_key in (
        'vpn.sessions.view','vpn.session.evidence.read'
      )
    )::bigint as package_capability_mapping_count,
    coalesce(
      (
        select registry.status
        from report_registry_v4 registry
        where registry.report_key='vpn.audit'
        order by registry.version desc
        limit 1
      ),
      'not_registered'
    ) as report_status,
    exists(
      select 1 from pg_roles
      where rolname like 'adlog_radius_manual_%'
         or rolname like 'adlog_radius_consumer_%'
    ) as ephemeral_login_exists,
    exists(
      select 1 from pg_stat_activity
      where application_name in (
        'sli_stage9_radius_manual_worker',
        'sli_stage9_radius_session_consumer_worker'
      )
        and pid<>pg_backend_pid()
    ) as manual_worker_session_exists,
    false as continuous_runtime_enabled,
    false as autostart_enabled
from acquisition_source_instances source
join acquisition_consumer_subscriptions subscription
  on subscription.source_instance_id=source.source_instance_id
join acquisition_stream_cursors cursor_row
  on cursor_row.source_instance_id=subscription.source_instance_id
 and cursor_row.stream_id=subscription.stream_id
 and cursor_row.transport_binding=subscription.transport_binding
join domains domain_row
  on lower(domain_row.fqdn)=lower(source.organization_scope)
left join radius_vpn_session_coverage_v1 coverage
  on coverage.domain_id=domain_row.id
where source.source_kind='windows.nps.radius'
  and subscription.consumer_id='sli.windows.vpn-radius';

revoke all on radius_vpn_operations_v1 from public;
grant select on radius_vpn_operations_v1 to adlog_user;

reset role;
revoke create on schema public
from adlog_vpn_session_reader_owner;

set local role adlog_storage_owner;
insert into schema_migrations(version,name)
values (63,'radius_vpn_operations_read_boundary')
on conflict(version) do update set name=excluded.name;

commit;
