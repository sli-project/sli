begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_runtime_collection_blocks_v38'));

do $$
begin
    if to_regclass('public.runtime_collection_blocks') is not null
       and exists(select 1 from runtime_collection_blocks) then
        raise exception 'rollback 038 refused: runtime_collection_blocks contains audit state';
    end if;
end
$$;

drop table if exists runtime_collection_blocks;
delete from schema_migrations where version=38 and name='runtime_collection_blocks';

commit;
