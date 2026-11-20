begin;
select pg_advisory_xact_lock(hashtext('sli_default_policy_reconcile_v340'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=340 and name='default_policy_reconcile')
       or exists(select 1 from public.schema_migrations where version>340) then
        raise exception 'default_policy_reconcile_340_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
do $$ declare saved record; derived record;
begin
    select * into strict saved from public.default_policy_restore_v340 where signature='public.ensure_default_qw_policy_v262(text,integer,text)';
    execute saved.definition;
    -- Policies registered by the new function are removed; the retired originals become active again.
    for derived in select p.policy_id,p.policy_version from public.semantic_risk_policies p
        where p.source_kind='qw_signal' and p.policy_id ~ '^default:qw[.][a-z-]+:[a-f0-9]{32}:r[a-f0-9]{12}$' loop
        begin
            delete from public.semantic_risk_policy_subscriptions where policy_id=derived.policy_id and policy_version=derived.policy_version;
            delete from public.semantic_policy_admission where policy_id=derived.policy_id and policy_version=derived.policy_version;
            delete from public.semantic_risk_policies where policy_id=derived.policy_id and policy_version=derived.policy_version;
        exception when foreign_key_violation then
            raise exception 'default_policy_340_rollback_in_use' using errcode='55000';
        end;
    end loop;
    update public.semantic_risk_policies p set lifecycle_status='shadow'
        from public.semantic_policy_admission a where a.policy_id=p.policy_id and a.policy_version=p.policy_version
          and a.updated_by='system:defaults-superseded';
    update public.semantic_policy_admission set enabled=true,updated_by='system:defaults',updated_at=now()
        where updated_by='system:defaults-superseded';
end $$;
drop function public.default_qw_policy_effective_id_v340(text,integer,text);
drop table public.default_policy_restore_v340;
delete from public.schema_migrations where version=340;
reset role;
commit;
