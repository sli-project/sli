-- No evidence, permissions or lifecycle history is removed by rollback.
begin;
select pg_advisory_xact_lock(hashtext('ad_log_plugin_state_v152'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from schema_migrations where version=152 and name='plugin_state')
       or exists(select 1 from schema_migrations where version>152) then
        raise exception 'rollback 152 prerequisites failed';
    end if;
    if exists(select 1 from plugin_state_v1 where configured or last_data_at_utc is not null)
       or exists(select 1 from plugin_installations_v1 where component_runtime='draining') then
        raise exception 'rollback 152 refuses observed state or active drain';
    end if;
end
$$;
drop function set_plugin_enabled_v1(text,boolean,bigint,text,bigint,boolean);
drop function finish_remote_access_plugin_drain_v1();
drop function observe_remote_access_plugin_v1(boolean,boolean);
drop function read_plugin_states_v1();
drop table plugin_state_v1;
create or replace function read_plugin_runtime_queue_nonterminal_v1()
returns bigint language sql stable security definer set search_path=pg_catalog,public
as $$
    select count(*)::bigint from public.acquisition_delivery_outbox
    where delivery_state in ('queued','leased','failed','quarantined')
$$;
delete from schema_migrations where version=152 and name='plugin_state';
commit;
