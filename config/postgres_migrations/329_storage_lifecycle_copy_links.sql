-- Exact event membership: range BRIN cannot prune sparse, long entity blocks.
-- Both indexes have one key and complementary partial predicates. No payload,
-- roles, INCLUDE columns or denormalized copy of the links is stored.
-- CONCURRENTLY requires autocommit; the build uses the same canonical owner
-- as the SET LOCAL ROLE transactions before and after it. A failed build has
-- no ledger marker; rerunning this file removes its incomplete indexes first.
select pg_advisory_lock(hashtext('sli_storage_lifecycle_copy_links_v329'));
begin;
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=328 and name='storage_lifecycle_evidence_lock')
       or exists(select 1 from public.schema_migrations where version>=329) then
        raise exception 'storage_lifecycle_copy_links_329_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
commit;
set role adlog_storage_owner;
drop index concurrently if exists public.sli_lifecycle_links_multi_v329;
drop index concurrently if exists public.sli_lifecycle_links_single_v329;
create index concurrently sli_lifecycle_links_multi_v329
    on public.event_entity_link_blocks_v2 using gin(event_ids) with (fastupdate=off)
    where cardinality(event_ids)>1;
create index concurrently sli_lifecycle_links_single_v329
    on public.event_entity_link_blocks_v2(first_event_id)
    where cardinality(event_ids)=1;
reset role;
begin;
set local role adlog_storage_owner;
do $$ begin
    if (select count(*) from pg_index where indexrelid in
        ('public.sli_lifecycle_links_multi_v329'::regclass,'public.sli_lifecycle_links_single_v329'::regclass)
        and indisvalid and indisready)<>2 then
        raise exception 'storage_lifecycle_copy_links_329_indexes_invalid' using errcode='55000';
    end if;
end $$;
insert into public.schema_migrations(version,name) values(329,'storage_lifecycle_copy_links');
reset role;
commit;
select pg_advisory_unlock(hashtext('sli_storage_lifecycle_copy_links_v329'));
