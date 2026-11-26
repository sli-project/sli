begin;
select pg_advisory_xact_lock(hashtext('sli_home_read_indexes424'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations
           where version=420 and name='password_rule_identity')
       or exists(select 1 from public.schema_migrations where version>=424) then
        raise exception 'home_read_indexes424_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

create index event_hot_home_changes424 on public.event_hot
    (domain_id,event_kind,time_created_utc desc,event_id desc);
create index finding_event_copy_identity424 on public.finding_event_copies337
    (domain_id,event_kind,event_id,time_created_utc,finding_id);
create index finding_event_copy_subject424 on public.finding_event_copies337
    (finding_id,(event_kind in (4728,4729,4732,4733,4756,4757,4719)) desc,time_created_utc desc,event_id desc);

-- Expose only membership for the requested IDs, as the existing scalar
-- publication check does. The API login cannot read the publication table.
create function public.home_published_findings424(p_ids bigint[]) returns table(finding_id bigint)
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select p.finding_id
    from public.semantic_finding_publications p where p.finding_id=any(p_ids)
$$;
revoke all on function public.home_published_findings424(bigint[]) from public;
grant execute on function public.home_published_findings424(bigint[]) to adlog_user;

insert into public.schema_migrations(version,name) values(424,'home_read_indexes');
commit;
