-- Evidence-preserving rollback for migration 085.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_dc_powershell_origin_context_v85')
);

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=85 and name='dc_powershell_origin_context'
    ) then
        raise exception 'migration 085 rollback requires its marker';
    end if;
    if exists(
        select 1 from event_facts_v2
        where powershell_process_id is not null
    ) then
        raise exception 'rollback is unsafe while PowerShell process facts exist';
    end if;
end
$$;

set local role adlog_storage_owner;

alter table event_facts_v2
    drop constraint event_facts_v2_powershell_process_id_bounded,
    drop column powershell_process_id;

delete from schema_migrations
where version=85 and name='dc_powershell_origin_context';

commit;
