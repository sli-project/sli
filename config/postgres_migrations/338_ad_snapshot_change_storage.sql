begin;
select pg_advisory_xact_lock(hashtext('sli_ad_snapshot_change_storage_v338'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=336 and name='event_storage_read_grants')
       or exists(select 1 from public.schema_migrations where version>=338) then
        raise exception 'ad_snapshot_change_storage_338_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- No FK to the seven-day snapshot ring: short changes outlive their source.
create table public.ad_snapshot_change_history (
    observed_at timestamptz not null check(isfinite(observed_at)),
    record_id varchar(64) not null check(record_id ~ '^[0-9a-f]{64}$'),
    batch_id varchar(64) not null check(batch_id ~ '^[0-9a-f]{64}$'),
    manifest_id uuid not null,
    domain_id bigint not null,
    family varchar(32) not null check(family in ('users_v2','computers_v6','gpo_v2')),
    record_kind varchar(16) not null default 'history' check(record_kind in ('history','changes','changes_header')),
    ordinal integer not null default 0 check(ordinal>=0),
    payload_json text not null check(octet_length(payload_json)<=65536 and jsonb_typeof(payload_json::jsonb)='object'),
    object_id text generated always as (coalesce(payload_json::jsonb->>'object_id',payload_json::jsonb->>'object_guid',payload_json::jsonb->>'user_id')) stored check(length(object_id)<=2048),
    attribute text generated always as (payload_json::jsonb->>'field') stored check(length(attribute)<=2048),
    before_value varchar(2048),
    after_value varchar(2048),
    -- Snapshot comparison does not establish who made a change.
    actor varchar(512),
    primary key(observed_at,record_kind,record_id)
) partition by range(observed_at);
create index on public.ad_snapshot_change_history(domain_id,family,observed_at,batch_id,record_kind);
create index on public.ad_snapshot_change_history(manifest_id,family,record_kind);
revoke all on public.ad_snapshot_change_history from public,adlog_user;
grant select on public.ad_snapshot_change_history to adlog_user;
grant select,insert on public.ad_snapshot_change_history to adlog_storage_lifecycle_worker;

create function public.create_ad_snapshot_change_partition(p_observed timestamptz) returns void
language plpgsql security definer set search_path=pg_catalog,public as $$
declare m date; next_month date; child text;
begin
    if p_observed is null or not isfinite(p_observed) then
        raise exception 'ad_snapshot_change_partition_date_invalid' using errcode='22023';
    end if;
    m:=date_trunc('month',p_observed at time zone 'UTC')::date;
    next_month:=(m+interval '1 month')::date;
    child:='ad_snapshot_change_history_m'||to_char(m,'YYYYMM');
    if to_regclass(format('public.%I',child)) is not null then return; end if;
    perform pg_advisory_xact_lock(hashtext('sli_ad_snapshot_change_partitions_v338'));
    if to_regclass(format('public.%I',child)) is null then
        execute format('create table public.%I partition of public.ad_snapshot_change_history for values from (%L) to (%L)',
            child,m::text||' 00:00:00+00',next_month::text||' 00:00:00+00');
        execute format('revoke all on public.%I from public,adlog_user',child);
    end if;
end $$;
revoke all on function public.create_ad_snapshot_change_partition(timestamptz) from public,adlog_user;
grant execute on function public.create_ad_snapshot_change_partition(timestamptz) to adlog_storage_lifecycle_worker;

-- Drop only complete expired months; retain the month containing the cutoff.
create function public.expire_ad_snapshot_change_partitions(p_cutoff timestamptz) returns integer
language plpgsql security definer set search_path=pg_catalog,public as $$
declare child record; removed integer:=0;
begin
    if p_cutoff is null or not isfinite(p_cutoff) then
        raise exception 'ad_snapshot_change_partition_date_invalid' using errcode='22023';
    end if;
    perform pg_advisory_xact_lock(hashtext('sli_ad_snapshot_change_partitions_v338'));
    for child in select c.relname from pg_inherits i join pg_class c on c.oid=i.inhrelid
        join pg_namespace n on n.oid=c.relnamespace
        where i.inhparent='public.ad_snapshot_change_history'::regclass and n.nspname='public'
          and c.relname ~ '^ad_snapshot_change_history_m[0-9]{6}$'
    loop
        if (to_date(right(child.relname,6),'YYYYMM')+interval '1 month') at time zone 'UTC' <= p_cutoff then
            execute format('drop table public.%I',child.relname);
            removed:=removed+1;
        end if;
    end loop;
    return removed;
end $$;
revoke all on function public.expire_ad_snapshot_change_partitions(timestamptz) from public,adlog_user;
grant execute on function public.expire_ad_snapshot_change_partitions(timestamptz) to adlog_storage_lifecycle_delete;

select public.create_ad_snapshot_change_partition(current_timestamp);
insert into public.schema_migrations(version,name) values(338,'ad_snapshot_change_storage');
reset role;
commit;
