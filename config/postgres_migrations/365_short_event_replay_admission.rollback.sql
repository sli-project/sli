begin;
select pg_advisory_xact_lock(hashtext('sli_short_event_replay_admission365'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not pg_has_role(session_user,'adlog_user','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=365 and name='short_event_replay_admission')
       or exists(select 1 from public.schema_migrations where version>365) then
        raise exception 'short_event_replay_admission365_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
drop trigger attest_short_event_replay365 on public.event_hot;
create or replace function public.write_short_events349(p_rows jsonb) returns table(groups bigint,summaries bigint,attested bigint)
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    perform public.create_event_storage_partitions(d,d) from (
        select distinct ((value->>'time_created_utc')::timestamptz at time zone 'UTC')::date as d from jsonb_array_elements(p_rows)
    ) days order by d;
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
reset role;
-- Retain already quarantined packets and their reasons across rollback.
alter table public.sli_agent_packet_quarantine drop constraint sli_agent_packet_quarantine_reason_code_check;
alter table public.sli_agent_packet_quarantine add constraint sli_agent_packet_quarantine_reason_code_check
    check(reason_code in ('source_event_allocation_hash_mismatch','published_source_event_hash_mismatch')) not valid;
reset role;
set local role adlog_storage_owner;
delete from public.schema_migrations where version=365 and name='short_event_replay_admission';
reset role;
commit;
