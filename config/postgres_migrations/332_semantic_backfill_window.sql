-- Bounded source discovery; no raw bodies or additional hot-layer indexes.
begin;
select pg_advisory_xact_lock(hashtext('sli_semantic_backfill_window_v332'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=331 and name='semantic_producer_coverage')
       or exists(select 1 from public.schema_migrations where version>=332) then
        raise exception 'semantic_backfill_window_332_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
alter table public.semantic_producer_coverage add column source_unavailable_ids int8multirange not null default '{}';
create function public.semantic_backfill_window_v332(p_after bigint,p_size integer,p_mode text,p_version text)
returns table(id bigint,event_key text,stream text,provider_name text,source_available boolean,keywords text,
    reset_keywords jsonb,present_kinds jsonb,decided boolean)
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
begin
    if p_after is null or p_after<0 or p_size is null or p_size not between 1 and 65536
       or p_mode is null or p_mode not in ('facts-v1','investigation-v1','findings-v1')
       or p_version is null or length(p_version) not between 1 and 128 then
        raise exception 'semantic_backfill_window_budget_invalid' using errcode='22023';
    end if;
    return query
    with cores as materialized (
        select e.* from public.events_v2_core e where e.id>p_after order by e.id limit p_size
    ), packets as materialized (
        select distinct r.id as raw_id,i.packet_id,i.event_rows,i.packet
        from (select distinct e.raw_log_file_id from cores e) refs
        join public.raw_log_files r on r.id=refs.raw_log_file_id
        join public.sli_agent_packet_inbox i on i.packet_id=case
            when r.file_path ~ '^agent-packet:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            then substr(r.file_path,14)::uuid end
        join public.sli_agent_receipts receipt on receipt.packet_id=i.packet_id
        where i.imported_at is not null and receipt.receipt->>'status'='committed' and i.envelope=receipt.envelope
          and (receipt.module_id='sli.windows.ad-dc' or (receipt.module_id='sli.file-audit' and i.packet->'header'->>'channel'='Security'))
    ), native_rows as materialized (
        -- Expand each packet once, rather than invoking the scalar reader per event.
        select p.raw_id,r.row->>'record_id' as record_id,r.row->>'event_id' as event_id,
            (r.row->>'time_created')::timestamptz as at,
            receipt.module_id
        from packets p join public.sli_agent_receipts receipt on receipt.packet_id=p.packet_id
        cross join lateral jsonb_array_elements(p.event_rows) r(row)
        where r.row->>'computer_name'=p.packet->'header'->>'source'
          and r.row->>'channel'=p.packet->'header'->>'channel'
    ), native as (
        select e.id from cores e join native_rows r on r.raw_id=e.raw_log_file_id
          and r.record_id=e.event_record_id::text and r.event_id=e.event_id::text
          and r.at between e.time_created_utc-interval '1 microsecond' and e.time_created_utc+interval '1 microsecond'
          and (r.module_id='sli.windows.ad-dc' or e.event_id in (4608,4624,4625,4634,4719,1102,4656,4658,4659,4660,4663,4664,4670,4907,5140,5142,5143,5144,5145,5168))
        group by e.id having count(*)=1
    )
    select e.id,e.event_id::text,c.value,coalesce(p.value,''),
        n.id is not null or exists(select 1 from public.storage_v2_archive_blocks b
            where b.archive_kind='event' and b.state='published' and b.first_event_id<=e.id and b.last_event_id>=e.id),
        k.value,coalesce(ctx.values,'[]'::jsonb),
        coalesce((select jsonb_agg(o.job_kind) from public.semantic_processing_outbox o
            where o.source_event_id=e.id and o.semantic_contract_version=1 and o.processor_id='semantic-shadow' and o.processor_version=p_version),'[]'::jsonb),
        coalesce(coverage.decided_ids @> e.id,false)
    from cores e join public.storage_v2_channel c on c.id=e.channel_id
    left join public.storage_v2_provider p on p.id=e.provider_id
    left join public.storage_v2_keywords k on k.id=e.keywords_id
    left join native n on n.id=e.id
    left join public.semantic_producer_coverage coverage on coverage.runtime_mode=p_mode and coverage.processor_version=p_version
    left join lateral (
        select jsonb_agg(rk.value) as values from public.events_v2_core reset
        join public.storage_v2_channel rc on rc.id=reset.channel_id and rc.value='Security'
        join public.storage_v2_provider rp on rp.id=reset.provider_id and rp.value='Microsoft-Windows-Security-Auditing'
        left join public.storage_v2_keywords rk on rk.id=reset.keywords_id
        where p_mode='investigation-v1' and e.event_id=4624 and c.value='Security' and p.value='Microsoft-Windows-Security-Auditing'
          and reset.domain_id=e.domain_id and reset.event_id=4724 and reset.target_user_sid=e.target_user_sid
          and lower(nullif(btrim(reset.target_user_sid),''))=lower(nullif(btrim(e.target_user_sid),''))
          and length(e.target_user_sid)<=184 and e.target_user_sid ~ '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$'
          and e.time_created_utc>reset.time_created_utc and e.time_created_utc<=reset.time_created_utc+interval '1 hour'
    ) ctx on true order by e.id;
end $$;
revoke all on function public.semantic_backfill_window_v332(bigint,integer,text,text) from public;
grant execute on function public.semantic_backfill_window_v332(bigint,integer,text,text) to adlog_semantic_worker;
insert into public.schema_migrations(version,name) values(332,'semantic_backfill_window');
reset role;
commit;
