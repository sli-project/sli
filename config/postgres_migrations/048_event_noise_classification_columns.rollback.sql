begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_event_noise_columns_v48'));

do $$
begin
    if exists (select 1 from schema_migrations where version=49) then
        raise exception 'roll back migration 049 before migration 048';
    end if;
end
$$;

alter table events_v2_core
    drop constraint if exists events_v2_core_noise_catalog_version,
    drop constraint if exists events_v2_core_noise_class,
    drop column if exists noise_catalog_version,
    drop column if exists noise_class;

delete from schema_migrations
where version=48 and name='event_noise_classification_columns';

commit;
