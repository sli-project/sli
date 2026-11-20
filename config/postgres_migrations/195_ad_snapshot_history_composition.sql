-- Preserve the families actually bound to an immutable manifest. A family
-- absent in the preceding slot starts a partial baseline, never a deletion diff.
begin;
select pg_advisory_xact_lock(hashtext('sli_ad_snapshot_history_composition_v195'));
select pg_advisory_xact_lock(hashtext('sli_ad_snapshot_change_history_v1'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=194 and name='agent_deployment_scope')
       or not exists(select 1 from public.schema_migrations where version=165 and name='ad_snapshot_change_history')
       or exists(select 1 from public.schema_migrations where version>=195) then
        raise exception 'migration 195 prerequisites failed';
    end if;
end $$;

create or replace function public.ad_snapshot_history_confirmation_guard_v165() returns trigger
language plpgsql security invoker set search_path=pg_catalog,public as $$
declare expected_previous uuid;
begin
    if tg_op='DELETE' and current_user='postgres' and session_user='adlog_user' then
        return old;
    end if;
    if tg_op<>'INSERT' then
        raise exception 'AD snapshot history confirmations are immutable';
    end if;
    if not exists(select 1 from public.ad_snapshot_manifests m
        join public.ad_snapshot_manifest_sources s on s.manifest_id=m.manifest_id
        where m.manifest_id=new.manifest_id and m.domain_id=new.domain_id
          and m.slot_start_utc=new.observed_at and s.family=new.family
          and encode(s.payload_sha256,'hex')=new.source_sha256) then
        raise exception 'AD snapshot history confirmation source mismatch';
    end if;
    -- Do not skip over collection gaps to an older source of this family.
    select m.manifest_id into expected_previous from public.ad_snapshot_manifests m
    where m.manifest_id=(select prior.manifest_id from public.ad_snapshot_manifests prior
        where prior.domain_id=new.domain_id and prior.slot_start_utc<new.observed_at
        order by prior.slot_start_utc desc limit 1)
      and exists(select 1 from public.ad_snapshot_manifest_sources s
          where s.manifest_id=m.manifest_id and s.family=new.family);
    if new.previous_manifest_id is distinct from expected_previous then
        raise exception 'AD snapshot history confirmation predecessor mismatch';
    end if;
    if expected_previous is not null and not exists(
        select 1 from public.ad_snapshot_manifest_sources s
        where s.manifest_id=expected_previous and s.family=new.family
          and encode(s.payload_sha256,'hex')=new.previous_sha256) then
        raise exception 'AD snapshot history confirmation predecessor hash mismatch';
    end if;
    return new;
end $$;
alter function public.ad_snapshot_history_confirmation_guard_v165() owner to postgres;
revoke all on function public.ad_snapshot_history_confirmation_guard_v165() from public;

create or replace procedure public.expire_ad_snapshot_confirmed_ring_v165(p_manifest_id uuid)
language plpgsql security definer set search_path=pg_catalog,public as $$
declare anchor_domain bigint; cutoff timestamptz;
begin
    if session_user<>'adlog_user' then
        raise exception 'AD snapshot expiry may be called only by adlog_user' using errcode='42501';
    end if;
    perform pg_advisory_xact_lock(hashtext('sli_ad_snapshot_change_history_v1'));
    perform pg_advisory_xact_lock(hashtext('ad_log_reports_ad_snapshot_seven_day_ring_expiry'));
    select domain_id,slot_start_utc-interval '7 days' into anchor_domain,cutoff
    from public.ad_snapshot_manifests where manifest_id=p_manifest_id;
    if not found then
        raise exception 'AD snapshot expiry requires a published manifest';
    end if;
    -- Require a verified receipt for EVERY bound history source, on both
    -- sides of a pair. No receipt is invented for an absent optional family.
    if exists(select 1 from public.ad_snapshot_manifests m
        join public.ad_snapshot_manifest_sources s on s.manifest_id=m.manifest_id
        left join lateral (
            select prior.manifest_id from public.ad_snapshot_manifests prior
            where prior.domain_id=m.domain_id and prior.slot_start_utc<m.slot_start_utc
            order by prior.slot_start_utc desc limit 1
        ) p on true
        left join public.ad_snapshot_manifest_sources ps
            on ps.manifest_id=p.manifest_id and ps.family=s.family
        where m.domain_id=anchor_domain and s.family in ('users_v2','computers_v6','gpo_v2')
          and not exists(select 1 from public.ad_snapshot_history_confirmations h
            where h.manifest_id=m.manifest_id and h.family=s.family and h.domain_id=m.domain_id
              and h.observed_at=m.slot_start_utc and h.source_sha256=encode(s.payload_sha256,'hex')
              and (
                -- An expired predecessor remains identified by its durable
                -- receipt. While it is hot, its exact family/hash must match.
                (p.manifest_id is null)
                or (ps.manifest_id is null and h.previous_manifest_id is null and h.previous_sha256 is null)
                or (ps.manifest_id is not null and h.previous_manifest_id=p.manifest_id
                    and h.previous_sha256=encode(ps.payload_sha256,'hex'))
              ))) then
        raise exception 'AD snapshot expiry refuses unconfirmed snapshots';
    end if;
    -- Keep the existing fence for unbound compatibility snapshots.
    if exists(select 1 from public.users_report_v2_snapshots s where s.domain_id=anchor_domain
        and s.captured_at_utc<=cutoff and not exists(select 1 from public.ad_snapshot_manifest_sources m
            where m.family='users_v2' and m.source_id=s.snapshot_id::text))
      or exists(select 1 from public.computers_v6_source_snapshots s where s.domain_id=anchor_domain
        and s.captured_at_utc<=cutoff and not exists(select 1 from public.ad_snapshot_manifest_sources m
            where m.family='computers_v6' and m.source_id=s.snapshot_uuid::text))
      or exists(select 1 from public.gpo_report_v2_source_snapshots s where s.domain_id=anchor_domain
        and s.created_at<=cutoff and not exists(select 1 from public.ad_snapshot_manifest_sources m
            where m.family='gpo_v2' and m.source_id=s.source_run_id::text)) then
        raise exception 'AD snapshot expiry refuses unconfirmed compatibility snapshots';
    end if;
    call public.expire_ad_snapshot_seven_day_ring(p_manifest_id);
end $$;
alter procedure public.expire_ad_snapshot_confirmed_ring_v165(uuid) owner to postgres;
revoke all on procedure public.expire_ad_snapshot_confirmed_ring_v165(uuid) from public;
grant execute on procedure public.expire_ad_snapshot_confirmed_ring_v165(uuid) to adlog_user;
revoke all on procedure public.expire_ad_snapshot_seven_day_ring(uuid) from adlog_user;
insert into public.schema_migrations(version,name) values(195,'ad_snapshot_history_composition');
commit;
