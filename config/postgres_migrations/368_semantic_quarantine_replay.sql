begin;
select pg_advisory_xact_lock(hashtext('sli_semantic_quarantine_replay368'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or to_regrole('adlog_semantic_worker') is null
       or not exists(select 1 from public.schema_migrations where version=366 and name='semantic_archive_authorization_reader')
       or exists(select 1 from public.schema_migrations where version>=368)
       or (select relowner from pg_class where oid=to_regclass('public.semantic_control_audit')) is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'semantic_quarantine_replay368_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- Reuse the installed semantic login. No new credential or broader worker role.
grant select(action,target,details) on public.semantic_control_audit to adlog_semantic_worker;
-- Do not let a replay caller forge policy admissions or another audit action.
create function public.record_semantic_quarantine_resolution368(p_target text,p_details jsonb) returns void
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    if p_details->>'job_id' is distinct from p_target
       or coalesce(p_details->>'outcome','') not in ('replayed','failed','closed') then
        raise exception 'semantic_quarantine_receipt_invalid' using errcode='22023';
    end if;
    insert into public.semantic_control_audit(action,target,actor,details)
        values('semantic_quarantine_resolution',p_target,session_user,p_details);
end $$;
revoke all on function public.record_semantic_quarantine_resolution368(text,jsonb) from public;
grant execute on function public.record_semantic_quarantine_resolution368(text,jsonb) to adlog_semantic_worker;
create index semantic_quarantine_receipts368 on public.semantic_control_audit(action,target)
    where action='semantic_quarantine_resolution';

insert into public.schema_migrations(version,name) values(368,'semantic_quarantine_replay');
reset role;
commit;
