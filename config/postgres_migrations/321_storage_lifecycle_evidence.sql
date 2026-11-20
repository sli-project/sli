-- Bounded evidence discovery through the existing reader; no additional login or DSN.
begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_storage_lifecycle_evidence_v321'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not pg_has_role(session_user,'adlog_user','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=320 and name='semantic_import_summary')
       or exists(select 1 from public.schema_migrations where version>=321) then
        raise exception 'storage_lifecycle_321_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
create function public.storage_lifecycle_evidence_v321(p_after bigint,p_upper bigint,p_codes integer[],p_channel text,p_provider text)
returns table(id bigint)
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
begin
    if p_after is null or p_after<0 or p_upper is null or p_upper<p_after or p_upper-p_after>65536
       or p_codes is null or cardinality(p_codes) not between 1 and 256
       or array_position(p_codes,null) is not null
       or p_channel is null or length(p_channel) not between 1 and 1024
       or p_provider is null or length(p_provider) not between 1 and 1024 then
        raise exception 'storage_lifecycle_evidence_budget_invalid' using errcode='22023';
    end if;
    -- Materialize only this id window's catalog descriptors before probing chains.
    return query
    with eligible as materialized (
        select e.id from public.events_v2_core e
        join public.storage_v2_channel c on c.id=e.channel_id
        join public.storage_v2_provider p on p.id=e.provider_id
        where e.id>p_after and e.id<=p_upper and e.event_id=any(p_codes)
          and c.value=p_channel and p.value=p_provider
    )
    select e.id from eligible e where
        exists(select 1 from public.normalized_events n
            join public.canonical_action_evidence a using(normalized_event_id) where n.source_event_id=e.id)
        or exists(select 1 from public.finding_evidence f where f.event_id=e.id)
        or exists(select 1 from public.detections d where d.primary_event_id=e.id)
        or exists(select 1 from public.investigation_events i where i.event_db_id=e.id)
        or exists(select 1 from public.event_links l where l.source_event_id=e.id or l.target_event_id=e.id)
        or exists(select 1 from public.entity_states s where s.evidence_event_id=e.id)
        or exists(select 1 from public.entity_state_current s where s.source_event_db_id=e.id)
    order by e.id;
end $$;
revoke all on function public.storage_lifecycle_evidence_v321(bigint,bigint,integer[],text,text) from public;
reset role;
-- Like storage_lifecycle_setting_v319, use the existing table reader as owner.
-- The worker receives only the fixed, read-only projection, never table grants.
alter function public.storage_lifecycle_evidence_v321(bigint,bigint,integer[],text,text) owner to adlog_user;
grant execute on function public.storage_lifecycle_evidence_v321(bigint,bigint,integer[],text,text) to adlog_storage_lifecycle_worker;
set local role adlog_storage_owner;
insert into public.schema_migrations(version,name) values(321,'storage_lifecycle_evidence');
reset role;
commit;
