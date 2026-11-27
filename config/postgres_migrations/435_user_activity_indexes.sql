begin;
select pg_advisory_xact_lock(hashtext('sli_user_activity_indexes435'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=424 and name='home_read_indexes')
       or exists(select 1 from public.schema_migrations where version>=435) then
        raise exception 'user_activity_indexes435_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- Store the compact recorder identity so the coverage count can be answered
-- by a covering index without reading the raw event or its JSON.
create function public.user_logon_recorder435(p_method jsonb) returns bigint
language sql immutable strict set search_path=pg_catalog,pg_temp as $$
    select case when p_method->>'$channel'='Security'
            and p_method->>'$provider'='Microsoft-Windows-Security-Auditing'
            and pg_input_is_valid(p_method->>'$server_id','pg_catalog.int8')
        then (p_method->>'$server_id')::bigint end
$$;
revoke all on function public.user_logon_recorder435(jsonb) from public;
grant execute on function public.user_logon_recorder435(jsonb) to adlog_storage_worker;

create function public.user_workplace_type435(p_method jsonb) returns smallint
language sql immutable strict set search_path=pg_catalog,pg_temp as $$
    select case btrim(p_method->>'LogonType',
        U&'\0009\000A\000B\000C\000D\0020\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000')
        when '2' then 2::smallint when '10' then 10::smallint when '11' then 11::smallint end
$$;
revoke all on function public.user_workplace_type435(jsonb) from public;
grant execute on function public.user_workplace_type435(jsonb) to adlog_storage_worker;

-- The event writers copy the hot row into cold facts positionally. Keep the
-- two row types compatible. Populate the hot fields in one rewrite, then
-- leave them writable for the positional inserts and maintain them on write.
alter table public.event_hot
    add column ad_user_logon_recorder435 bigint generated always as
        (case when event_kind=4624 then public.user_logon_recorder435(method) end) stored,
    add column ad_user_workplace_type435 smallint generated always as
        (case when event_kind=4624 then public.user_workplace_type435(method) end) stored;
alter table public.event_hot alter column ad_user_logon_recorder435 drop expression,
    alter column ad_user_workplace_type435 drop expression;
alter table public.event_cold_facts add column ad_user_logon_recorder435 bigint,
    add column ad_user_workplace_type435 smallint;

create function public.store_user_logon_recorder435() returns trigger
language plpgsql set search_path=pg_catalog,pg_temp as $$
begin
    new.ad_user_logon_recorder435 := case when new.event_kind=4624
        then public.user_logon_recorder435(new.method) end;
    new.ad_user_workplace_type435 := case when new.event_kind=4624
        then public.user_workplace_type435(new.method) end;
    return new;
end $$;
revoke all on function public.store_user_logon_recorder435() from public;
create trigger user_logon_recorder435 before insert or update of event_kind,method,ad_user_logon_recorder435,ad_user_workplace_type435
    on public.event_hot for each row
    when (new.event_kind=4624 or new.ad_user_logon_recorder435 is not null or new.ad_user_workplace_type435 is not null)
    execute function public.store_user_logon_recorder435();

create index event_hot_user_logon_coverage435 on public.event_hot
    (domain_id,time_created_utc,ad_user_logon_recorder435) include (actor)
    where ad_user_logon_recorder435 is not null;

-- Keep covered entries within the B-tree tuple size even for UTF-8 input.
-- The second index keeps longer source/actor combinations readable.
create index event_hot_user_workplace435 on public.event_hot (domain_id,time_created_utc)
    include (actor,source,event_id,ad_user_logon_recorder435,ad_user_workplace_type435)
    where ad_user_logon_recorder435 is not null and ad_user_workplace_type435 is not null
        and actor ilike 'S-1-%' and source is not null and octet_length(actor)+octet_length(source)<=2400;
create index event_hot_user_workplace_long435 on public.event_hot (domain_id,time_created_utc)
    where event_kind=4624 and method->>'$channel'='Security'
        and method->>'$provider'='Microsoft-Windows-Security-Auditing' and actor ilike 'S-1-%' and source is not null
        and btrim(method->>'LogonType',U&'\0009\000A\000B\000C\000D\0020\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000') collate "C" in ('2','10','11')
        and octet_length(actor)+octet_length(source)>2400;

-- These partitioned indexes cover existing and future children. Normalize
-- trailing whitespace in the same way as the Users readers.
do $$ declare target text; ord text; begin
    foreach target in array array['event_hot','event_cold_facts','event_cold_daily'] loop
        ord := case when target='event_cold_daily' then 'day' else 'time_created_utc' end;
        execute format($index$
            create index %I on public.%I (domain_id,
                lower(btrim(actor,U&'\0009\000A\000B\000C\000D\0020\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000') collate "C"),%I)
            where event_kind=4624 and method->>'$channel'='Security'
                and method->>'$provider'='Microsoft-Windows-Security-Auditing' and actor ilike 'S-1-%%'
            $index$, target||'_user_logon_account435',target,ord);
        if target<>'event_hot' then execute format($index$
            create index %I on public.%I (domain_id,%I)
            where event_kind=4624 and method->>'$channel'='Security'
                and method->>'$provider'='Microsoft-Windows-Security-Auditing' and actor ilike 'S-1-%%'
                and source is not null
                and btrim(method->>'LogonType',U&'\0009\000A\000B\000C\000D\0020\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000') collate "C" in ('2','10','11')
            $index$, target||'_user_workplace435',target,ord);
        end if;
        execute format($index$
            create index %I on public.%I (domain_id,upper(actor),%I)
            where event_kind in (4624,4625)
            $index$, target||'_user_card_sid435',target,ord);
        execute format($index$
            create index %I on public.%I (domain_id,lower(actor),%I)
            where event_kind=4625
            $index$, target||'_user_card_name435',target,ord);
    end loop;
end $$;

insert into public.schema_migrations(version,name) values(435,'user_activity_indexes');
commit;
