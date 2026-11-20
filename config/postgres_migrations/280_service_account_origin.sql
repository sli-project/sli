begin;
select pg_advisory_xact_lock(hashtext('ad_log_service_account_origin_v280'));
do $$ begin
    if not exists(select 1 from public.schema_migrations where version=279 and name='agent_sequence_recovery') then
        raise exception 'migration 280 requires exact migration 279 agent_sequence_recovery';
    end if;
    if exists(select 1 from public.schema_migrations where version=280) then
        raise exception 'migration 280 already applied or occupied';
    end if;
end $$;

-- Classification metadata, not an authentication or authorization decision.
alter table public.auth_users add column is_service boolean not null default false;

-- Recover only explicit report-subject provenance. Names and disabled status
-- are not proof. Successful setup audit also covers a later issuance failure.
update public.auth_users u set is_service=true
where exists (select 1 from public.auth_api_keys k where k.report_subject_id=u.id)
   or exists (
       select 1 from public.access_audit_v4 a
       where a.subject_type='user' and a.subject_id=u.id
         and a.actor_type='local_operator' and a.outcome='ok'
         and ((a.action='report_api_key_issued' and a.target_type='api_key')
           or (a.action='report_key_capabilities_created' and a.target_type='ad_domain'))
   );

insert into public.schema_migrations(version,name) values(280,'service_account_origin');
commit;
