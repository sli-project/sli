begin;
select pg_advisory_xact_lock(hashtext('sli_short_storage_retention342'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=340 and name='default_policy_reconcile')
       or exists(select 1 from public.schema_migrations where version>=342) then
        raise exception 'short_storage_retention342_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- The context writer records GPO changes in the same transaction as its snapshot.
-- The application login remains read-only on the history table.
grant select,insert on public.ad_snapshot_change_history,public.ad_snapshot_history_confirmations to adlog_context_worker;
grant execute on function public.create_ad_snapshot_change_partition(timestamptz) to adlog_context_worker;

create function public.expire_short_storage_partitions342(p_hot timestamptz,p_cold timestamptz,p_snapshots timestamptz)
returns table(hot_partitions integer,cold_partitions integer,snapshot_partitions integer)
language plpgsql security definer set search_path=pg_catalog,public as $$
declare child record; upper_day date; cutoff timestamptz; bounds text[]; actual_upper timestamptz;
begin
    if p_hot is null or p_cold is null or p_snapshots is null
       or not isfinite(p_hot) or not isfinite(p_cold) or not isfinite(p_snapshots)
       or p_cold>p_hot or p_hot>current_timestamp or p_snapshots>current_timestamp then
        raise exception 'short_storage_retention_cutoff_invalid' using errcode='22023';
    end if;
    hot_partitions:=0; cold_partitions:=0; snapshot_partitions:=0;
    perform pg_advisory_xact_lock(hashtext('sli_event_storage_partitions_v335'));
    perform pg_advisory_xact_lock(hashtext('sli_ad_snapshot_change_partitions_v338'));
    for child in
        select c.relname,p.relname as parent,pg_get_expr(c.relpartbound,c.oid) as partition_bounds from pg_inherits i
        join pg_class c on c.oid=i.inhrelid join pg_namespace n on n.oid=c.relnamespace
        join pg_class p on p.oid=i.inhparent join pg_namespace pn on pn.oid=p.relnamespace
        where n.nspname='public' and pn.nspname='public'
          and ((p.relname='event_hot' and c.relname~'^event_hot_d[0-9]{8}$')
            or (p.relname in ('event_cold_facts','event_cold_daily') and c.relname~'^event_cold_(facts|daily)_m[0-9]{6}$')
            or (p.relname='ad_snapshot_change_history' and c.relname~'^ad_snapshot_change_history_m[0-9]{6}$'))
        order by p.relname,c.relname
    loop
        if child.parent='event_hot' then
            upper_day:=to_date(right(child.relname,8),'YYYYMMDD')+1; cutoff:=p_hot;
        else
            upper_day:=(to_date(right(child.relname,6),'YYYYMM')+interval '1 month')::date;
            cutoff:=case when child.parent='ad_snapshot_change_history' then p_snapshots else p_cold end;
        end if;
        bounds:=regexp_match(child.partition_bounds,'^FOR VALUES FROM \(''([^'']+)''\) TO \(''([^'']+)''\)$');
        if bounds is null then
            raise exception 'short_storage_partition_bounds_invalid' using errcode='55000';
        end if;
        if child.parent='event_cold_daily' then actual_upper:=bounds[2]::date::timestamp at time zone 'UTC';
        else actual_upper:=bounds[2]::timestamptz; end if;
        if actual_upper<>upper_day::timestamp at time zone 'UTC' then
            raise exception 'short_storage_partition_bounds_invalid' using errcode='55000';
        end if;
        if actual_upper<=cutoff then
            execute format('drop table public.%I',child.relname);
            if child.parent='event_hot' then hot_partitions:=hot_partitions+1;
            elsif child.parent='ad_snapshot_change_history' then snapshot_partitions:=snapshot_partitions+1;
            else cold_partitions:=cold_partitions+1; end if;
        end if;
    end loop;
    return next;
end $$;
revoke all on function public.expire_short_storage_partitions342(timestamptz,timestamptz,timestamptz) from public,adlog_user,adlog_context_worker,adlog_storage_lifecycle_worker;
grant execute on function public.expire_short_storage_partitions342(timestamptz,timestamptz,timestamptz) to adlog_storage_lifecycle_delete;
insert into public.schema_migrations(version,name) values(342,'short_storage_retention');
reset role;
commit;
