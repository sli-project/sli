begin;
select pg_advisory_xact_lock(hashtext('sli_password_worker_throughput396'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=396 and name='password_worker_throughput')
       or exists(select 1 from public.schema_migrations where version>396) then
        raise exception 'password_worker_throughput396_rollback_preflight' using errcode='55000'; end if;
end $$;
set local role adlog_storage_owner;

do $$ declare saved record; begin
    for saved in select * from public.password_restore396 loop
        if not exists(select 1 from pg_proc p where p.oid=saved.signature and p.proowner=saved.owner_oid
                      and p.proacl is not distinct from saved.acl
                      and pg_get_functiondef(p.oid)=saved.installed_definition) then
            raise exception 'password_worker_throughput396_rollback_metadata_changed' using errcode='55000'; end if;
        execute saved.definition;
    end loop;
end $$;

-- Restore managed history policies retired by a poll after this upgrade.
-- A later administrator decision or live revision takes precedence.
do $$ declare route record; retired public.password_policy_retired393; begin
    for route in
        update public.password_pass_state393 p set history_pin=old.history_pin,
            history_from=old.history_from,history_to=old.history_to
        from public.password_retired_history396 old
        where p.scope_digest=old.scope_digest and p.rule_id=old.rule_id
          and p.live_pin=old.live_pin and p.history_pin is null
        returning p.rule_id,p.history_pin
    loop
        select r.* into retired from public.password_policy_retired393 r
        join public.semantic_control_audit a on a.id=r.retirement_audit_id
        join public.schema_migrations m on m.version=396 and a.occurred_at>=m.applied_at
        where r.policy_id='default:'||route.rule_id||':'||substr(route.history_pin,1,32)
          and r.policy_version=1;
        if not found then continue; end if;
        update public.semantic_risk_policies p set lifecycle_status=retired.previous_status,updated_at=now()
        where p.policy_id=retired.policy_id and p.policy_version=retired.policy_version and p.lifecycle_status='deprecated'
          and retired.retirement_audit_id=(select a.id from public.semantic_control_audit a
              where a.action='password_policy_lifecycle' and a.target=p.policy_id||':'||p.policy_version
              order by a.occurred_at desc,a.id desc limit 1)
          and not exists(select 1 from public.semantic_control_audit a
              where a.action='policy_admission' and a.target=p.policy_id||':'||p.policy_version
                and a.id>retired.retirement_audit_id);
        if found then
            perform public.password_policy_provenance_v275(retired.policy_id,retired.policy_version,'seed');
            delete from public.password_policy_retired393 r
            where r.policy_id=retired.policy_id and r.policy_version=retired.policy_version;
        end if;
    end loop;
end $$;

drop table public.password_retired_history396,public.password_restore396;
delete from public.schema_migrations where version=396 and name='password_worker_throughput';
reset role;
commit;
