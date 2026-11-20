-- S2 dual writes. Retention/detach and reader cutover belong to later steps.
begin;
select pg_advisory_xact_lock(hashtext('sli_event_storage_s2_v335'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'event_storage_s2_335_preflight' using errcode='55000';
    end if;
    if not exists(select 1 from public.schema_migrations where version=334 and name='account_decoy_restore')
       or exists(select 1 from public.schema_migrations where version>=335) then
        raise exception 'event_storage_s2_335_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

create table public.event_hot (
    event_id bigint not null,
    time_created_utc timestamptz not null check(isfinite(time_created_utc)),
    event_kind integer not null check(event_kind>0),
    domain_id bigint not null,
    actor varchar(512),
    target varchar(512),
    source varchar(512),
    computer varchar(512) not null,
    method jsonb not null check(jsonb_typeof(method)='object' and octet_length(method::text)<=8192),
    outcome jsonb not null check(jsonb_typeof(outcome)='object' and octet_length(outcome::text)<=8192),
    fields jsonb not null check(jsonb_typeof(fields)='object' and octet_length(fields::text)<=32768),
    primary key(time_created_utc,event_id)
) partition by range(time_created_utc);

create table public.event_cold_facts (like public.event_hot including all)
    partition by range(time_created_utc);

create table public.event_cold_daily (
    day date not null check(isfinite(day)),
    -- Fixed-width index: host strings can be large multibyte values. Exact
    -- dimensions are compared during upsert, so a hash collision fails closed.
    grouping_key bytea not null check(octet_length(grouping_key)=32),
    event_kind integer not null check(event_kind>0),
    domain_id bigint not null,
    actor varchar(512),
    target varchar(512),
    source varchar(512),
    computer varchar(512) not null,
    method jsonb not null check(jsonb_typeof(method)='object' and octet_length(method::text)<=8192),
    outcome jsonb not null check(jsonb_typeof(outcome)='object' and octet_length(outcome::text)<=8192),
    event_count bigint not null check(event_count>0),
    first_seen_utc timestamptz not null,
    last_seen_utc timestamptz not null,
    check(first_seen_utc<=last_seen_utc and isfinite(first_seen_utc) and isfinite(last_seen_utc)),
    check((first_seen_utc at time zone 'UTC')::date=day and (last_seen_utc at time zone 'UTC')::date=day),
    primary key(day,grouping_key)
) partition by range(day);

revoke all on public.event_hot,public.event_cold_facts,public.event_cold_daily from public,adlog_user;
grant select,insert on public.event_hot,public.event_cold_facts to adlog_storage_worker;
grant select,insert,update on public.event_cold_daily to adlog_storage_worker;
grant select on public.event_hot,public.event_cold_facts,public.event_cold_daily to adlog_storage_lifecycle_worker;

-- Inclusive day range; UTC boundaries do not depend on the caller's timezone.
-- The storage service can create any required horizon; no history cutoff here.
create function public.create_event_storage_partitions(first_day date,last_day date) returns void
language plpgsql security definer set search_path=pg_catalog,public as $$
declare d date; m date; next_month date; child text; parent text;
begin
    if first_day is null or last_day is null or not isfinite(first_day) or not isfinite(last_day) or first_day>last_day then
        raise exception 'event_storage_partition_range_invalid' using errcode='22023';
    end if;
    -- Fast path avoids a global DDL lock for normal, pre-created partitions.
    if not exists (
        select 1 from generate_series(first_day::timestamp,last_day::timestamp,interval '1 day') g(d)
        where to_regclass(format('public.%I','event_hot_d'||to_char(g.d,'YYYYMMDD'))) is null
    ) and not exists (
        select 1 from generate_series(date_trunc('month',first_day::timestamp),date_trunc('month',last_day::timestamp),interval '1 month') g(d)
        cross join (values('event_cold_facts'),('event_cold_daily')) p(name)
        where to_regclass(format('public.%I',p.name||'_m'||to_char(g.d,'YYYYMM'))) is null
    ) then return; end if;
    perform pg_advisory_xact_lock(hashtext('sli_event_storage_partitions_v335'));
    d:=first_day;
    loop
        child:='event_hot_d'||to_char(d,'YYYYMMDD');
        if to_regclass(format('public.%I',child)) is null then
            execute format('create table public.%I partition of public.event_hot for values from (%L) to (%L)',
                child,d::text||' 00:00:00+00',(d+1)::text||' 00:00:00+00');
            execute format('revoke all on public.%I from public,adlog_user',child);
        end if;
        exit when d=last_day;
        d:=d+1;
    end loop;
    m:=date_trunc('month',first_day::timestamp)::date;
    loop
        next_month:=(m+interval '1 month')::date;
        foreach parent in array array['event_cold_facts','event_cold_daily'] loop
            child:=parent||'_m'||to_char(m,'YYYYMM');
            if to_regclass(format('public.%I',child)) is null then
                if parent='event_cold_facts' then
                    execute format('create table public.%I partition of public.%I for values from (%L) to (%L)',
                        child,parent,m::text||' 00:00:00+00',next_month::text||' 00:00:00+00');
                else
                    execute format('create table public.%I partition of public.%I for values from (%L) to (%L)',child,parent,m,next_month);
                end if;
                execute format('revoke all on public.%I from public,adlog_user',child);
            end if;
        end loop;
        exit when next_month>last_day;
        m:=next_month;
    end loop;
end $$;
revoke all on function public.create_event_storage_partitions(date,date) from public,adlog_user;
grant execute on function public.create_event_storage_partitions(date,date) to adlog_storage_worker,adlog_storage_lifecycle_worker;
select public.create_event_storage_partitions((current_timestamp at time zone 'UTC')::date,(current_timestamp at time zone 'UTC')::date+31);
insert into public.schema_migrations(version,name) values(335,'event_storage_s2');
reset role;
commit;
