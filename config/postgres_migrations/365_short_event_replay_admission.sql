begin;
select pg_advisory_xact_lock(hashtext('sli_short_event_replay_admission365'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not pg_has_role(session_user,'adlog_user','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=362 and name='detection_event_clock')
       or exists(select 1 from public.schema_migrations where version>=365) then
        raise exception 'short_event_replay_admission365_preflight' using errcode='55000';
    end if;
end $$;
reset role;
alter table public.sli_agent_packet_quarantine drop constraint sli_agent_packet_quarantine_reason_code_check;
alter table public.sli_agent_packet_quarantine add constraint sli_agent_packet_quarantine_reason_code_check
    check(reason_code in ('source_event_allocation_hash_mismatch','published_source_event_hash_mismatch',
                         'short_event_summary_conflict','short_event_attestation_failed'));
reset role;
set local role adlog_storage_owner;
create trigger attest_short_event_replay365 before update on public.event_hot
    for each row when (old.source_sha256 is null) execute function public.attest_short_event337();
create or replace function public.write_short_events349(p_rows jsonb) returns table(groups bigint,summaries bigint,attested bigint)
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    perform public.create_event_storage_partitions(d,d) from (
        select distinct ((value->>'time_created_utc')::timestamptz at time zone 'UTC')::date as d from jsonb_array_elements(p_rows)
    ) days order by d;
    -- Only a byte-for-byte equivalent short event may acquire missing proof.
    -- The UPDATE trigger reuses the packet/receipt/native-representation admission;
    -- no hash or origin supplied by the caller is copied into the stored row.
    with incoming as materialized (
        select r.* from jsonb_array_elements(p_rows) j
        cross join lateral jsonb_populate_record(null::public.event_hot,j.value) r
    )
    update public.event_hot h set method=i.method
    from incoming i
    where h.time_created_utc=i.time_created_utc and h.event_id=i.event_id
      and h.source_sha256 is null and i.method ? '$packet_id'
      and (h.event_kind,h.domain_id,h.actor,h.target,h.source,h.computer,
           h.method-'$origin'-'$packet_id'-'$packet_ordinal',h.outcome,h.fields)
          is not distinct from
          (i.event_kind,i.domain_id,i.actor,i.target,i.source,i.computer,
           i.method-'$origin'-'$packet_id'-'$packet_ordinal',i.outcome,i.fields);
    -- Preserve the fact copy, without adding the replay to daily totals again.
    update public.event_cold_facts f
    set source_sha256=h.source_sha256,event_record_id=h.event_record_id,method=h.method
    from public.event_hot h, jsonb_array_elements(p_rows) j
    where h.time_created_utc=(j.value->>'time_created_utc')::timestamptz
      and h.event_id=(j.value->>'event_id')::bigint
      and f.time_created_utc=h.time_created_utc and f.event_id=h.event_id
      and f.source_sha256 is null and h.source_sha256 is not null
      and (f.event_kind,f.domain_id,f.actor,f.target,f.source,f.computer,f.method-'$origin',f.outcome,f.fields)
          is not distinct from
          (h.event_kind,h.domain_id,h.actor,h.target,h.source,h.computer,h.method-'$origin',h.outcome,h.fields);
    return query
with incoming as materialized (
                select r.*,j.value->>'layer' as layer from jsonb_array_elements(p_rows) j
                cross join lateral jsonb_populate_record(null::public.event_hot,j.value) r
            ), inserted as (
                insert into public.event_hot(event_id,time_created_utc,event_kind,domain_id,actor,target,source,computer,method,outcome,fields)
                select event_id,time_created_utc,event_kind,domain_id,actor,target,source,computer,method,outcome,fields
                from incoming order by time_created_utc,event_id
                on conflict(time_created_utc,event_id) do nothing returning *
            ), facts as (
                insert into public.event_cold_facts
                select h.* from inserted h join incoming i using(time_created_utc,event_id) where i.layer='fact'
                on conflict(time_created_utc,event_id) do nothing returning event_id
            ), daily as materialized (
                select (h.time_created_utc at time zone 'UTC')::date as day,
                       h.event_kind,h.domain_id,h.actor,h.target,h.source,h.computer,h.method,h.outcome,
                       count(*) as event_count,min(h.time_created_utc) as first_seen_utc,max(h.time_created_utc) as last_seen_utc
                from inserted h join incoming i using(time_created_utc,event_id) where i.layer='summary'
                group by (h.time_created_utc at time zone 'UTC')::date,
                         h.event_kind,h.domain_id,h.actor,h.target,h.source,h.computer,h.method,h.outcome
            ), summaries as (
                insert into public.event_cold_daily as current(day,grouping_key,event_kind,domain_id,actor,target,source,computer,method,outcome,event_count,first_seen_utc,last_seen_utc)
                select day,sha256(convert_to(jsonb_build_array(event_kind,domain_id,actor,target,source,computer,method,outcome)::text,'UTF8')),
                       event_kind,domain_id,actor,target,source,computer,method,outcome,event_count,first_seen_utc,last_seen_utc
                from daily order by 1,2
                on conflict(day,grouping_key) do update set event_count=current.event_count+excluded.event_count,
                    first_seen_utc=least(current.first_seen_utc,excluded.first_seen_utc),
                    last_seen_utc=greatest(current.last_seen_utc,excluded.last_seen_utc)
                where (current.event_kind,current.domain_id,current.actor,current.target,current.source,current.computer,current.method,current.outcome)
                    is not distinct from (excluded.event_kind,excluded.domain_id,excluded.actor,excluded.target,excluded.source,excluded.computer,excluded.method,excluded.outcome)
                returning day
            )
            select (select count(*) from daily),(select count(*) from summaries),
                (select count(*) from incoming i where exists(
                    select 1 from inserted h where h.time_created_utc=i.time_created_utc and h.event_id=i.event_id and h.source_sha256 is not null)
                    or exists(select 1 from public.event_hot h where h.time_created_utc=i.time_created_utc and h.event_id=i.event_id and h.source_sha256 is not null));
end $$;
revoke all on function public.write_short_events349(jsonb) from public;
grant execute on function public.write_short_events349(jsonb) to adlog_user,adlog_storage_worker;
insert into public.schema_migrations(version,name) values(365,'short_event_replay_admission');
reset role;
commit;
