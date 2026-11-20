-- Preserve existing update reasons; add the MSI-owned ZIP rejection outcome.
begin;
select pg_advisory_xact_lock(hashtext('sli_agent_msi_update_result_v196'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 196 requires membership in adlog_storage_owner';
    end if;
    if not exists(select 1 from public.schema_migrations where version=195 and name='ad_snapshot_history_composition')
       or exists(select 1 from public.schema_migrations where version>=196) then
        raise exception 'migration 196 requires exact migration 195 ad_snapshot_history_composition and unused version 196';
    end if;
end $$;
set local role adlog_storage_owner;
do $$
declare
    target record;
    previous text;
begin
    for target in select * from (values
        ('sli_agent_update_results','sli_agent_update_results_reason_check'),
        ('sli_agent_update_wave_members','sli_agent_update_wave_members_reason_check')
    ) as targets(table_name,constraint_name) loop
        select pg_get_expr(conbin,conrelid) into strict previous
        from pg_constraint
        where conrelid=format('public.%I',target.table_name)::regclass
          and conname=target.constraint_name and contype='c';
        execute format('alter table public.%I drop constraint %I',target.table_name,target.constraint_name);
        execute format('alter table public.%I add constraint %I check ((%s) or reason=''agent_update_msi_required'')',
                       target.table_name,target.constraint_name,previous);
    end loop;
end $$;
reset role;
insert into public.schema_migrations(version,name) values(196,'agent_msi_update_result');
commit;
