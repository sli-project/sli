begin;
select pg_advisory_xact_lock(hashtext('sli_dc_task_service_catalog401'));
set local lock_timeout='5s';
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not pg_has_role(session_user,'adlog_user','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=401 and name='dc_task_service_catalog')
       or exists(select 1 from public.schema_migrations where version>401) then
        raise exception 'dc_task_service401_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
-- Existing findings and decisions remain visible. Stop future evaluation and
-- cancel only pending deliveries owned by these two pinned catalog policies.
update public.semantic_risk_policies p set lifecycle_status='disabled'
from public.dc_catalog_policies401 pin
where p.policy_id=pin.policy_id and p.policy_version=1 and p.definition_sha256=pin.definition_sha256;
-- Publication takes the policy lock before the outbox admission lock.
select pg_advisory_xact_lock(hashtext('notification_outbox_admission'));
update public.notification_outbox j set state='cancelled',result_code='subscription_changed',
    lease_token=null,lease_until=null,updated_at=now()
from public.semantic_security_scenarios s join public.dc_catalog_policies401 pin using(scenario_kind)
where j.publication_scenario_id=s.scenario_id and j.state in('pending','retry','sending');
drop function public.dc_catalog_notification_domain401(uuid,uuid,bigint[]);
drop function public.enqueue_dc_catalog_notifications401(uuid);
drop function public.copy_dc_catalog_evidence401(bigint,uuid);
drop function public.dc_catalog_finding401(bigint,uuid);
drop function public.read_dc_catalog_action401(text,integer,uuid);
do $$ declare original text; begin
    select attestation into strict original from public.dc_catalog_restore401;
    execute original;
end $$;
drop table public.dc_catalog_restore401;
-- Keep trusted live/history origin for observations already attested by 401.
-- It also prevents a restored upgrade from treating history as new input.
drop table public.dc_catalog_policies401;
reset role;
set local role adlog_user;
drop function public.lock_dc_catalog_host401(bigint,bigint);
reset role;
delete from public.schema_migrations where version=401 and name='dc_task_service_catalog';
commit;
