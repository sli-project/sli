-- Like 351, this file uses the runner's psql autocommit session. PostgreSQL
-- cannot build a partitioned index CONCURRENTLY: create metadata-only parents,
-- build each existing leaf online, then attach it without scanning its table.
select pg_advisory_lock(hashtext('sli_short_event_id_indexes357'));
begin;
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=355 and name='semantic_short_cursor')
       or not exists(select 1 from public.schema_migrations where version=356 and name='detection_source_branches')
       or exists(select 1 from public.schema_migrations where version>=357)
       or (select relowner from pg_class where oid='public.event_hot'::regclass) is distinct from 'adlog_storage_owner'::regrole
       or (select relowner from pg_class where oid='public.event_cold_facts'::regclass) is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'short_event_id_indexes357_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
-- IF NOT EXISTS resumes a build interrupted before the ledger was committed.
-- New partitions inherit their index even while the parent is not yet valid.
create index if not exists event_hot_event_id357 on only public.event_hot(event_id);
create index if not exists event_cold_facts_event_id357 on only public.event_cold_facts(event_id);
commit;
set role adlog_storage_owner;

-- An interrupted concurrent leaf build can leave an invalid, unattached index.
-- Never discard a valid attached index or rebuild a populated leaf under a
-- write-blocking CREATE INDEX on the parent.
select format('drop index concurrently %s',i.indexrelid::regclass)
from pg_inherits t join pg_class c on c.oid=t.inhrelid
join pg_namespace n on n.oid=c.relnamespace
join pg_class x on x.relnamespace=n.oid and x.relname=c.relname||'_event_id357'
join pg_index i on i.indexrelid=x.oid and i.indrelid=c.oid
where t.inhparent in ('public.event_hot'::regclass,'public.event_cold_facts'::regclass)
  and not (i.indisvalid and i.indisready)
  and not exists(select 1 from pg_inherits a where a.inhrelid=x.oid)
order by t.inhparent,c.oid
\gexec

select format('create index concurrently if not exists %I on %s(event_id)',c.relname||'_event_id357',c.oid::regclass)
from pg_inherits t join pg_class c on c.oid=t.inhrelid
where t.inhparent in ('public.event_hot'::regclass,'public.event_cold_facts'::regclass)
  and not exists (
    select 1 from pg_inherits a join pg_index i on i.indexrelid=a.inhrelid
    where i.indrelid=t.inhrelid and a.inhparent=case t.inhparent
      when 'public.event_hot'::regclass then 'public.event_hot_event_id357'::regclass
      else 'public.event_cold_facts_event_id357'::regclass end)
order by t.inhparent,c.oid
\gexec

reset role;
begin;
set local role adlog_storage_owner;
do $$
declare child record; parent_index regclass;
begin
    for child in
        select t.inhparent,c.oid,c.relname,n.nspname
        from pg_inherits t join pg_class c on c.oid=t.inhrelid join pg_namespace n on n.oid=c.relnamespace
        where t.inhparent in ('public.event_hot'::regclass,'public.event_cold_facts'::regclass)
        order by t.inhparent,c.oid
    loop
        parent_index:=case child.inhparent when 'public.event_hot'::regclass then 'public.event_hot_event_id357'::regclass
            else 'public.event_cold_facts_event_id357'::regclass end;
        if not exists(select 1 from pg_inherits a join pg_index i on i.indexrelid=a.inhrelid
                      where a.inhparent=parent_index and i.indrelid=child.oid) then
            execute format('alter index %s attach partition %I.%I',parent_index,child.nspname,child.relname||'_event_id357');
        end if;
    end loop;
    if exists (
        select 1 from (values('public.event_hot'::regclass,'public.event_hot_event_id357'::regclass),
                            ('public.event_cold_facts'::regclass,'public.event_cold_facts_event_id357'::regclass)) expected(tbl,idx)
        join pg_index i on i.indexrelid=expected.idx join pg_class c on c.oid=i.indexrelid
        join pg_attribute a on a.attrelid=expected.tbl and a.attname='event_id'
        where not (i.indisvalid and i.indisready) or i.indrelid<>expected.tbl
          or i.indnkeyatts<>1 or i.indnatts<>1 or i.indkey[0]<>a.attnum
          or i.indpred is not null or i.indexprs is not null
          or c.relam<>(select oid from pg_am where amname='btree')
          or c.relowner<>'adlog_storage_owner'::regrole
    ) then
        raise exception 'short_event_id_indexes357_indexes_invalid' using errcode='55000';
    end if;
end $$;
insert into public.schema_migrations(version,name) values(357,'short_event_id_indexes');
reset role;
commit;
select pg_advisory_unlock(hashtext('sli_short_event_id_indexes357'));
