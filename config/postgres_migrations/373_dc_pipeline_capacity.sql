begin;
select pg_advisory_xact_lock(hashtext('sli_dc_pipeline_capacity373'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not pg_has_role(session_user,'adlog_user','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=370 and name='password_producer_failures')
       or exists(select 1 from public.schema_migrations where version>=373) then
        raise exception 'dc_pipeline_capacity373_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_user;
-- 8 events / 53.4 ms = 1124 packets/minute with worker connection reuse.
-- Add 20%, rounded up to a 16-packet catch-up cycle: 1360/minute.
-- Only replace the uncustomized DC enrollment default:
-- signed templates and explicit administrator rate choices remain authoritative.
do $$ declare a record; control jsonb; begin
    for a in select * from public.sli_agents agent
        where status='active' and template_id is null
          and collection_policy->>'state'='active'
          and collection_policy->'rate_limit_per_minute'='120'::jsonb
          and exists(select 1 from jsonb_array_elements(assigned_modules) m
              where m->>'module_id'='sli.windows.ad-dc' and m->'enabled'='true'::jsonb)
          and not exists(select 1 from public.sli_agent_audit audit
              where audit.target=agent.id::text and audit.action='policy_update' and audit.actor<>'migration:373'
                and (audit.details->'changed_fields' ? 'rate_limit_per_minute'
                     or not(audit.details ? 'changed_fields')))
        order by id for update
    loop
        if a.policy_revision>=9007199254740991 then
            raise exception 'dc_pipeline_capacity373_revision_exhausted' using errcode='55000';
        end if;
        perform pg_advisory_xact_lock(hashtextextended('sli-agent-import:'||a.id::text,0));
        control:=jsonb_set(a.collection_policy,'{rate_limit_per_minute}','1360'::jsonb);
        insert into public.sli_agent_policy_history(agent_id,revision,assigned_modules,collection_policy)
            values(a.id,a.policy_revision,a.assigned_modules,a.collection_policy) on conflict do nothing;
        insert into public.sli_agent_policy_history(agent_id,revision,assigned_modules,collection_policy)
            values(a.id,a.policy_revision+1,a.assigned_modules,control);
        update public.sli_agents set collection_policy=control,policy_revision=a.policy_revision+1 where id=a.id;
        insert into public.sli_agent_audit(action,actor,target,details)
            values('policy_update','migration:373',a.id::text,jsonb_build_object(
                'migration',373,'direction','upgrade','revision',a.policy_revision+1,
                'rate_limit_per_minute',1360,'changed_fields',jsonb_build_array('rate_limit_per_minute')));
    end loop;
end $$;
set local role adlog_storage_owner;
insert into public.schema_migrations(version,name) values(373,'dc_pipeline_capacity');
reset role;
commit;
