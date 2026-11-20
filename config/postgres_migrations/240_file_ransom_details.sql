-- R02: retain scoped exclusion decisions without deleting native file rows.
begin;
select pg_advisory_xact_lock(hashtext('sli_file_ransom_details_v240'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=237 and name='entity_context_health')
       or not exists(select 1 from public.schema_migrations where version=232 and name='file_ransom')
       or exists(select 1 from public.schema_migrations where version>=240) then
        raise exception 'migration 240 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;

alter table public.semantic_file_ransom_members
    alter column episode_key drop not null,
    add column exclusion_json jsonb check(exclusion_json is null or coalesce((
        jsonb_typeof(exclusion_json)='object' and octet_length(exclusion_json::text)<=8192
        and exclusion_json ?& array['subject_sid','collection_scope_id','reason','approved_by','active_from','active_to']
        and length(exclusion_json->>'reason') between 1 and 500
        and length(exclusion_json->>'approved_by') between 1 and 128
        and exclusion_json->>'subject_sid' ~ '^S-1-([0-9]+-)*[0-9]+$'
        and exclusion_json->>'collection_scope_id'=scope_json->>'collection_scope_id'
        and (exclusion_json->>'active_to')::timestamptz>(exclusion_json->>'active_from')::timestamptz
        and (exclusion_json->>'active_to')::timestamptz-(exclusion_json->>'active_from')::timestamptz<=interval '31 days'),false)),
    add column evaluation_mode text check(evaluation_mode in ('test','shadow','enabled')),
    add column evaluated_at timestamptz not null default now(),
    add constraint file_ransom_member_decision check((episode_key is null)=(exclusion_json is not null));
create index file_ransom_member_result on public.semantic_file_ransom_members(result_id,evaluated_at desc);

-- Only the page's already authorized roots and result IDs reach this reader.
-- No direct table grants to the HTTP runtime, no source/binding activation.
create function public.read_file_ransom_details(p_roots jsonb,p_ids jsonb) returns jsonb
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare answer jsonb;
begin
    if jsonb_typeof(p_roots) is distinct from 'array' or jsonb_array_length(p_roots)>1000
       or jsonb_typeof(p_ids) is distinct from 'array' or jsonb_array_length(p_ids)>100 then
        raise exception 'file_ransom_details_invalid';
    end if;
    with selected as (
        select distinct on(m.result_id) m.*,e.first_seen,e.last_seen,e.incomplete
        from public.semantic_file_ransom_members m
        left join public.semantic_file_ransom_episodes e using(episode_key)
        where m.result_id in (select jsonb_array_elements_text(p_ids))
          and exists(select 1 from jsonb_to_recordset(p_roots) r(
              agent_id uuid,source_instance_id text,collection_scope_id text)
              where r.source_instance_id=m.scope_json->>'source_instance_id'
                and r.collection_scope_id=m.scope_json->>'collection_scope_id'
                and exists(select 1 from public.finding_evidence_source_bindings b
                    where b.installation_id=(m.scope_json->>'installation_id')::uuid
                      and b.plugin_id='sli.file-audit' and b.agent_id=r.agent_id
                      and b.source_instance_id=r.source_instance_id
                      and b.collection_scope_id=r.collection_scope_id
                      and b.source_generation=m.scope_json->>'source_generation'
                      and b.storage_kind='file_audit_observation'))
        order by m.result_id,m.evaluated_at desc,m.checkpoint_key
    ) select coalesce(jsonb_object_agg(result_id,jsonb_build_object(
        'state',case when exclusion_json is not null then 'excluded'
                     when evaluation_mode is null then 'details_unavailable'
                     when evaluation_mode='enabled' then 'admitted' else 'diagnostic' end,
        'episode_key',episode_key,'first_seen',first_seen,'last_seen',last_seen,
        'incomplete',incomplete,'evaluation_mode',evaluation_mode,
        'source_generation',scope_json->>'source_generation','exclusion',exclusion_json)),
        '{}'::jsonb) into answer from selected;
    return answer;
end $$;
revoke all on function public.read_file_ransom_details(jsonb,jsonb) from public;
grant execute on function public.read_file_ransom_details(jsonb,jsonb) to adlog_user;
insert into public.schema_migrations(version,name) values(240,'file_ransom_details');
commit;
