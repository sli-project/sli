begin;
select pg_advisory_xact_lock(hashtext('sli_password_pass_recovery393'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=393 and name='password_pass_recovery')
       or exists(select 1 from public.schema_migrations where version>393) then
        raise exception 'password_pass_recovery393_rollback_preflight' using errcode='55000'; end if;
end $$;
set local role adlog_storage_owner;

do $$ declare retired record; restored record; begin
    for retired in select * from public.password_policy_retired393 order by policy_id,policy_version loop
        update public.semantic_risk_policies p
        set lifecycle_status=retired.previous_status,updated_at=now()
        where p.policy_id=retired.policy_id and p.policy_version=retired.policy_version and p.lifecycle_status='deprecated'
          and retired.retirement_audit_id=(
              select audit.id from public.semantic_control_audit audit
              where audit.action='password_policy_lifecycle' and audit.target=p.policy_id||':'||p.policy_version
              order by audit.occurred_at desc,audit.id desc limit 1)
          and not exists(select 1 from public.semantic_control_audit audit
              where audit.action='policy_admission' and audit.target=p.policy_id||':'||p.policy_version
              and audit.id>retired.retirement_audit_id);
        if found then
            perform public.password_policy_provenance_v275(retired.policy_id,retired.policy_version,'seed');
        end if;
    end loop;
    for restored in select * from public.password_restore393 loop
        if not exists(select 1 from pg_proc p where p.oid=restored.signature and p.proowner=restored.owner_oid
                      and p.proacl is not distinct from restored.acl
                      and pg_get_functiondef(p.oid)=restored.installed_definition) then
            raise exception 'password_pass_recovery393_rollback_metadata_changed' using errcode='55000'; end if;
        execute restored.definition;
    end loop;
end $$;

drop function public.password_live_execution393(jsonb,text);
drop function public.password_retire_policies393(jsonb,text,text,text);
drop function public.password_definition_revision393(text);
drop table public.password_policy_retired393;
drop table public.password_pass_state393;
drop table public.password_restore393;
delete from public.schema_migrations where version=393 and name='password_pass_recovery';
reset role;
commit;
