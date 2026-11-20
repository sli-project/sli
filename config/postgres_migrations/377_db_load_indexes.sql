begin;
select pg_advisory_xact_lock(hashtext('sli_db_load_indexes377'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=376 and name='workstation_import_isolation')
       or exists(select 1 from public.schema_migrations where version>=377) then
        raise exception 'db_load_indexes377_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- The delete worker classifies and confirms coverage in the same transaction.
-- Reader/producer roles receive no new deletion capability.
grant update,delete on public.semantic_processing_outbox to adlog_storage_lifecycle_delete;
grant insert,update on public.semantic_producer_coverage to adlog_storage_lifecycle_delete;
grant select on public.entity_identity_semantic_replays_v2 to adlog_storage_lifecycle_delete;

create index semantic_normalize_pending377 on public.semantic_processing_outbox(source_event_id)
    where job_kind='normalize_event' and status in ('queued','leased');
create index semantic_repair_reference377 on public.semantic_processing_outbox
    (source_event_id,(payload_json->>'original_job_id'))
    where payload_json->>'original_job_id' is not null;
create index semantic_replay_reference377 on public.entity_identity_semantic_replays_v2(replay_job_id);
create index finding_occurrences377 on public.finding_event_copies337(finding_id,event_kind,event_id);
create index event_hot_review_context377 on public.event_hot(domain_id,event_kind,time_created_utc)
    where source_sha256 is not null;

-- The aggregate used the same context classifier repeatedly. Keep its exact
-- result, but calculate each sample once and reuse the parameterized plan
-- across findings instead of replanning every partition for every row.
create table public.db_load_restore377(definition text not null,installed_definition text not null,
    owner_oid oid not null,acl aclitem[]);
revoke all on public.db_load_restore377 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
do $$ declare original text; body text; ordinary text; classification integer; aggregate_start integer;
    original_owner oid; original_acl aclitem[]; begin
    select pg_get_functiondef(oid),prosrc,proowner,proacl into strict original,body,original_owner,original_acl from pg_proc
        where oid='public.semantic_finding_review_v160(bigint)'::regprocedure
          and proowner='adlog_storage_owner'::regrole and prosecdef;
    if strpos(body,'), classified as (')=0 then
        raise exception 'db_load_indexes377_review_shape' using errcode='55000'; end if;
    body:=replace(body,'), classified as (','), classified as materialized (');
    classification:=strpos(body,'), classified as materialized (');
    aggregate_start:=strpos(body,E'\n    )\n    select jsonb_build_object');
    if aggregate_start<=classification then
        raise exception 'db_load_indexes377_aggregate_shape' using errcode='55000'; end if;
    ordinary:=substr(body,1,classification-1)||
        '), classified as materialized (select s.*, ''unknown''::text as bucket from review_samples s'||
        substr(body,aggregate_start);
    -- Non-4719 samples always had bucket=unknown. Avoid even planning their
    -- unused GPO/session branches, while retaining the same sample/aggregate.
    execute 'create or replace function public.semantic_finding_review_v160(p_id bigint) returns jsonb
        language plpgsql stable security definer set search_path=pg_catalog,public
        set plan_cache_mode=force_generic_plan as '||quote_literal('begin
            if not exists(select 1 from public.finding_event_copies337
                where finding_id=p_id and event_kind=4719) then return ('||ordinary||'); end if;
            return ('||body||'); end;');
    if not exists(select 1 from pg_proc where oid='public.semantic_finding_review_v160(bigint)'::regprocedure
        and proowner=original_owner and proacl is not distinct from original_acl and prosecdef) then
        raise exception 'db_load_indexes377_review_metadata_changed' using errcode='55000'; end if;
    insert into public.db_load_restore377
        select original,pg_get_functiondef(oid),proowner,proacl from pg_proc
        where oid='public.semantic_finding_review_v160(bigint)'::regprocedure;
end $$;

insert into public.schema_migrations(version,name) values(377,'db_load_indexes');
reset role;
commit;
