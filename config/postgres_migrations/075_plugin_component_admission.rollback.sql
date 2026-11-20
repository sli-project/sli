-- Guarded rollback for unused component admission foundation only.
begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_admission_v75'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 075 rollback requires storage owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=75 and name='plugin_component_admission'
    ) then
        raise exception 'migration 075 rollback requires exact marker';
    end if;
    if exists (select 1 from plugin_component_leases_v1) then
        raise exception 'migration 075 rollback forbidden after first lease';
    end if;
    if exists (
        select 1 from plugin_component_admission_v1
        where admission_mode<>'closed' or revision<>1
    ) then
        raise exception 'migration 075 rollback requires untouched closed seed';
    end if;
end
$$;

delete from schema_migrations
where version=75 and name='plugin_component_admission';

revoke execute on function acquire_plugin_component_lease_v1(
    uuid,text,text,text,text
) from adlog_radius_accounting_worker,adlog_radius_session_consumer;
revoke execute on function release_plugin_component_lease_v1(
    uuid,text,text
) from adlog_radius_accounting_worker,adlog_radius_session_consumer;
drop function release_plugin_component_lease_v1(uuid,text,text);
drop function acquire_plugin_component_lease_v1(uuid,text,text,text,text);
drop table plugin_component_leases_v1;
drop table plugin_component_admission_v1;

commit;
