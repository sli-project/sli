-- Preserve independently published GPO sources until their history is confirmed.
begin;
select pg_advisory_xact_lock(hashtext('sli_ad_snapshot_change_history_v1'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=201 and name='file_audit_semantic_source')
       or not exists(select 1 from public.schema_migrations where version=200 and name='agent_gpo_change_history')
       or exists(select 1 from public.schema_migrations where version>=202) then
        raise exception 'migration 202 prerequisites failed';
    end if;
end $$;
create function public.agent_gpo_history_expiry_guard_v202() returns trigger
language plpgsql security invoker set search_path=pg_catalog,public as $$
begin
    if tg_op='TRUNCATE' then raise exception 'GPO history sources cannot be truncated'; end if;
    if exists(
        select 1 from public.sli_agent_snapshot_cycles c
        join public.domains d on d.id=old.domain_id and d.domain_sid=c.domain_sid
          and d.domain_sid=c.policy->>'domain_sid' and lower(d.fqdn)=c.policy->>'domain_dns'
        left join lateral (select n.* from public.sli_agent_snapshot_cycles n
            where n.agent_id=c.agent_id and n.module_id='sli.gpo-snapshot' and n.slot_start_utc>c.slot_start_utc
            order by n.slot_start_utc,n.cycle_id limit 1) next on true
        where c.module_id='sli.gpo-snapshot' and c.publication_state='published'
          and c.gpo_source_run_id=old.source_run_id
          and (not exists(select 1 from public.ad_snapshot_history_confirmations h
                where h.manifest_id=c.cycle_id and h.family='gpo_v2' and h.domain_id=old.domain_id
                  and h.source_sha256=encode(old.payload_sha256,'hex'))
            or (next.publication_state='published'
              and next.policy->'source_instance_id' is not distinct from c.policy->'source_instance_id'
              and next.policy->'domain_sid' is not distinct from c.policy->'domain_sid'
              and next.policy->'domain_dns' is not distinct from c.policy->'domain_dns'
              and next.policy->'scope' is not distinct from c.policy->'scope'
              and not exists(select 1 from public.ad_snapshot_history_confirmations h
                where h.manifest_id=next.cycle_id and h.family='gpo_v2' and h.domain_id=old.domain_id)))) then
        raise exception 'GPO history expiry requires confirmed published sources';
    end if;
    return old;
end $$;
alter function public.agent_gpo_history_expiry_guard_v202() owner to postgres;
revoke all on function public.agent_gpo_history_expiry_guard_v202() from public;
create trigger agent_gpo_history_source_expiry before delete on public.gpo_report_v2_source_snapshots
for each row execute function public.agent_gpo_history_expiry_guard_v202();
create trigger agent_gpo_history_source_no_truncate before truncate on public.gpo_report_v2_source_snapshots
for each statement execute function public.agent_gpo_history_expiry_guard_v202();
insert into public.schema_migrations(version,name) values(202,'agent_gpo_history_expiry_fence');
commit;
