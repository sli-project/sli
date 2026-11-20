-- Clean rollback only before any lifecycle operation or registry state change.
begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_lifecycle_v73'));

do $$
declare
    v_seed record;
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'rollback 073 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=73 and name='plugin_lifecycle_registry'
    ) then
        raise exception 'rollback 073 requires exact migration marker';
    end if;
    if exists (select 1 from plugin_lifecycle_operations_v1) then
        raise exception 'rollback 073 forbidden after lifecycle operation';
    end if;
    select * into v_seed from plugin_installations_v1;
    if (select count(*) from plugin_installations_v1) <> 1
       or v_seed.plugin_id <> 'sli.remote-access'
       or v_seed.package_lifecycle <> 'validated'
       or v_seed.desired_activation <> 'disabled'
       or v_seed.observed_health <> 'unknown'
       or v_seed.component_runtime <> 'stopped'
       or v_seed.queue_state <> 'drained'
       or v_seed.revision <> 1
       or v_seed.detach_reader_ready
       or v_seed.read_report_parity then
        raise exception 'rollback 073 forbidden after registry state change';
    end if;
    if exists (
        select 1 from access_capability_assignments assignment
        join access_capabilities capability on capability.id=assignment.capability_id
        where capability.capability_key='plugins.manage'
    ) then
        raise exception 'rollback 073 forbidden after capability assignment';
    end if;
end
$$;

delete from access_package_capabilities mapping
using access_capabilities capability
where capability.id=mapping.capability_id
  and capability.capability_key='plugins.manage';
delete from access_capabilities where capability_key='plugins.manage';
delete from schema_migrations
where version=73 and name='plugin_lifecycle_registry';

drop function read_plugin_installations_v1(integer);
drop trigger plugin_lifecycle_operations_reject_update_delete
    on plugin_lifecycle_operations_v1;
drop trigger plugin_lifecycle_operations_reject_truncate
    on plugin_lifecycle_operations_v1;
drop function reject_plugin_lifecycle_operation_mutation_v1();
drop table plugin_lifecycle_operations_v1;
drop table plugin_installations_v1;

revoke all on schema public from adlog_plugin_lifecycle_owner;
revoke all on schema public from adlog_plugin_lifecycle_executor;
revoke adlog_plugin_lifecycle_executor from adlog_storage_owner;
revoke adlog_plugin_lifecycle_owner from adlog_storage_owner;
drop role adlog_plugin_lifecycle_executor;
drop role adlog_plugin_lifecycle_owner;

commit;
