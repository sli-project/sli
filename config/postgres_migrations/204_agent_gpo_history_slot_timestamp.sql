-- Repair migration 200: agent slots are canonical UTC text, confirmation times are timestamptz.
begin;
select pg_advisory_xact_lock(hashtext('sli_ad_snapshot_change_history_v1'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=202 and name='agent_gpo_history_expiry_fence')
       or not exists(select 1 from public.schema_migrations where version=203 and name='agent_semantic_timestamp_precision')
       or exists(select 1 from public.schema_migrations where version>=204) then
        raise exception 'migration 204 prerequisites failed';
    end if;
end $$;

create or replace function public.ad_snapshot_history_confirmation_guard_v165() returns trigger
language plpgsql security invoker set search_path=pg_catalog,public as $$
declare expected_previous uuid; anchor record; prior record;
begin
    if tg_op='DELETE' and current_user='postgres' and session_user='adlog_user' then return old; end if;
    if tg_op<>'INSERT' then raise exception 'AD snapshot history confirmations are immutable'; end if;
    if new.family='gpo_v2' and exists(select 1 from public.sli_agent_snapshot_cycles where cycle_id=new.manifest_id) then
        select c.*,s.domain_id,encode(s.payload_sha256,'hex') as source_hash into anchor
        from public.sli_agent_snapshot_cycles c join public.gpo_report_v2_source_snapshots s
          on s.source_run_id=c.gpo_source_run_id and s.import_status='completed'
        join public.domains d on d.id=s.domain_id and d.domain_sid=c.domain_sid
          and d.domain_sid=c.policy->>'domain_sid' and lower(d.fqdn)=c.policy->>'domain_dns'
        where c.cycle_id=new.manifest_id and c.module_id='sli.gpo-snapshot'
          and c.publication_state='published';
        if not found or anchor.domain_id<>new.domain_id or anchor.slot_start_utc::timestamptz<>new.observed_at
           or anchor.source_hash<>new.source_sha256 then
            raise exception 'GPO history confirmation source mismatch';
        end if;
        select c.*,s.domain_id,encode(s.payload_sha256,'hex') as source_hash into prior
        from public.sli_agent_snapshot_cycles c left join public.gpo_report_v2_source_snapshots s
          on s.source_run_id=c.gpo_source_run_id and s.import_status='completed' and s.domain_id=anchor.domain_id
        where c.agent_id=anchor.agent_id and c.module_id='sli.gpo-snapshot'
          and c.slot_start_utc<anchor.slot_start_utc
        order by c.slot_start_utc desc,c.cycle_id desc limit 1;
        if found and prior.publication_state='published' and prior.domain_id=anchor.domain_id
           and prior.policy->'source_instance_id' is not distinct from anchor.policy->'source_instance_id'
           and prior.policy->'domain_sid' is not distinct from anchor.policy->'domain_sid'
           and prior.policy->'domain_dns' is not distinct from anchor.policy->'domain_dns'
           and prior.policy->'scope' is not distinct from anchor.policy->'scope' then
            expected_previous:=prior.cycle_id;
        end if;
        if new.previous_manifest_id is distinct from expected_previous
           or (expected_previous is not null and new.previous_sha256 is distinct from prior.source_hash) then
            raise exception 'GPO history confirmation predecessor mismatch';
        end if;
        return new;
    end if;
    -- Keep the existing AD/legacy-GPO admission and expiry fences unchanged.
    if not exists(select 1 from public.ad_snapshot_manifests m
        join public.ad_snapshot_manifest_sources s on s.manifest_id=m.manifest_id
        where m.manifest_id=new.manifest_id and m.domain_id=new.domain_id
          and m.slot_start_utc=new.observed_at and s.family=new.family
          and encode(s.payload_sha256,'hex')=new.source_sha256) then
        raise exception 'AD snapshot history confirmation source mismatch';
    end if;
    select m.manifest_id into expected_previous from public.ad_snapshot_manifests m
    where m.manifest_id=(select p.manifest_id from public.ad_snapshot_manifests p
        where p.domain_id=new.domain_id and p.slot_start_utc<new.observed_at order by p.slot_start_utc desc limit 1)
      and exists(select 1 from public.ad_snapshot_manifest_sources s where s.manifest_id=m.manifest_id and s.family=new.family);
    if new.previous_manifest_id is distinct from expected_previous then
        raise exception 'AD snapshot history confirmation predecessor mismatch';
    end if;
    if expected_previous is not null and not exists(select 1 from public.ad_snapshot_manifest_sources s
        where s.manifest_id=expected_previous and s.family=new.family and encode(s.payload_sha256,'hex')=new.previous_sha256) then
        raise exception 'AD snapshot history confirmation predecessor hash mismatch';
    end if;
    return new;
end $$;
alter function public.ad_snapshot_history_confirmation_guard_v165() owner to postgres;
revoke all on function public.ad_snapshot_history_confirmation_guard_v165() from public;
insert into public.schema_migrations(version,name) values(204,'agent_gpo_history_slot_timestamp');
commit;
