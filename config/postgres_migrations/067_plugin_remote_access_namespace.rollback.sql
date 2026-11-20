-- Roll back only while the plugin namespace still contains its exact marker.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_plugin_remote_access_namespace_v67')
);

do $$
declare
    v_relation_count integer;
    v_routine_count integer;
    v_marker_count integer;
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'rollback 067 requires membership in adlog_storage_owner';
    end if;
    if exists (select 1 from schema_migrations where version>67) then
        raise exception 'rollback 067 is blocked by later migrations';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=67 and name='plugin_remote_access_namespace'
    ) then
        raise exception 'rollback 067 requires schema migration 067';
    end if;
    select count(*) into v_relation_count
    from pg_class as c
    join pg_namespace as n on n.oid=c.relnamespace
    where n.nspname='sli_plugin_remote_access'
      and c.relkind in ('r','p','v','m','S','f')
      and c.relname<>'plugin_namespace_contract_v1';
    select count(*) into v_routine_count
    from pg_proc as p
    join pg_namespace as n on n.oid=p.pronamespace
    where n.nspname='sli_plugin_remote_access';
    execute 'select count(*) from sli_plugin_remote_access.plugin_namespace_contract_v1 where plugin_id=''sli.remote-access'' and contract_id=''sli.plugin-postgresql-isolation.v1'' and contract_version=1'
    into v_marker_count;
    if v_relation_count<>0 or v_routine_count<>0 or v_marker_count<>1 then
        raise exception 'rollback 067 forbidden after plugin namespace use';
    end if;
end
$$;

set local role adlog_plugin_remote_access_owner;
drop table sli_plugin_remote_access.plugin_namespace_contract_v1;
drop schema sli_plugin_remote_access;
reset role;

delete from schema_migrations
where version=67 and name='plugin_remote_access_namespace';

revoke adlog_plugin_remote_access_runtime from adlog_storage_owner;
revoke adlog_plugin_remote_access_owner from adlog_storage_owner;
drop role adlog_plugin_remote_access_runtime;
drop role adlog_plugin_remote_access_owner;

commit;
