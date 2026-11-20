begin;
select pg_advisory_xact_lock(hashtext('sli_dc_pipeline_capacity373'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not pg_has_role(session_user,'adlog_user','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=373 and name='dc_pipeline_capacity')
       or exists(select 1 from public.schema_migrations where version>373) then
        raise exception 'dc_pipeline_capacity373_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_user;
-- Roll back only the still-current migration-issued policy. Keep subsequent
-- administrator edits and append policy history instead of rewriting old proof.
do $$ declare a record; control jsonb; begin
    for a in select agent.* from public.sli_agents agent
        where agent.status='active' and exists(
            select 1 from public.sli_agent_audit audit
            join public.sli_agent_policy_history h on h.agent_id=agent.id and h.revision=agent.policy_revision
            where audit.action='policy_update' and audit.actor='migration:373' and audit.target=agent.id::text
              and audit.details->>'direction'='upgrade' and audit.details->>'revision'=agent.policy_revision::text
              and agent.collection_policy=h.collection_policy and agent.assigned_modules=h.assigned_modules)
        order by agent.id for update
    loop
        if a.policy_revision>=9007199254740991 then
            raise exception 'dc_pipeline_capacity373_revision_exhausted' using errcode='55000';
        end if;
        perform pg_advisory_xact_lock(hashtextextended('sli-agent-import:'||a.id::text,0));
        control:=jsonb_set(a.collection_policy,'{rate_limit_per_minute}','120'::jsonb);
        insert into public.sli_agent_policy_history(agent_id,revision,assigned_modules,collection_policy)
            values(a.id,a.policy_revision+1,a.assigned_modules,control);
        update public.sli_agents set collection_policy=control,policy_revision=a.policy_revision+1 where id=a.id;
        insert into public.sli_agent_audit(action,actor,target,details)
            values('policy_update','migration:373',a.id::text,jsonb_build_object(
                'migration',373,'direction','rollback','revision',a.policy_revision+1,
                'rate_limit_per_minute',120,'changed_fields',jsonb_build_array('rate_limit_per_minute')));
    end loop;
end $$;
set local role adlog_storage_owner;
delete from public.schema_migrations where version=373 and name='dc_pipeline_capacity';
reset role;
commit;
