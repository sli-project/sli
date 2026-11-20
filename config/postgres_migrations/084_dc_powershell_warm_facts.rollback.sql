-- Evidence-preserving rollback for migration 084.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_dc_powershell_warm_facts_v84')
);

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=84 and name='dc_powershell_warm_facts'
    ) then
        raise exception 'migration 084 rollback requires its marker';
    end if;
    if exists(
        select 1 from event_facts_v2
        where powershell_user_name is not null
           or powershell_command_name is not null
           or powershell_script_block_text is not null
    ) then
        raise exception 'rollback is unsafe while PowerShell warm facts exist';
    end if;
end
$$;

set local role adlog_storage_owner;

alter table event_facts_v2
    drop constraint event_facts_v2_powershell_user_bounded,
    drop constraint event_facts_v2_powershell_command_bounded,
    drop constraint event_facts_v2_powershell_script_block_bounded,
    drop column powershell_user_name,
    drop column powershell_command_name,
    drop column powershell_script_block_text;

delete from schema_migrations
where version=84 and name='dc_powershell_warm_facts';

commit;
