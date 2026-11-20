-- Durable AD/GPO change publication confirmations; hot snapshots remain a seven-day ring.
begin;
select pg_advisory_xact_lock(hashtext('sli_ad_snapshot_change_history_v165'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 165 requires membership in adlog_storage_owner';
    end if;
    if exists(select 1 from public.schema_migrations where version=165) then
        raise exception 'migration 165 already recorded';
    end if;
    if not exists(select 1 from public.schema_migrations where version=164 and name='agent_instances')
       or exists(select 1 from public.schema_migrations where version>164) then
        raise exception 'migration 165 requires exact migration 164 agent_instances';
    end if;
    if to_regprocedure('public.expire_ad_snapshot_seven_day_ring(uuid)') is null then
        raise exception 'migration 165 requires the seven-day snapshot expiry procedure';
    end if;
end $$;

-- No foreign keys to the hot ring: receipts and pair hashes must survive its expiry.
create table public.ad_snapshot_history_confirmations (
    manifest_id uuid not null,
    family text not null check(family in ('users_v2','computers_v6','gpo_v2')),
    domain_id bigint not null check(domain_id>0),
    previous_manifest_id uuid,
    source_sha256 text not null check(source_sha256 ~ '^[a-f0-9]{64}$'),
    previous_sha256 text check(previous_sha256 ~ '^[a-f0-9]{64}$'),
    batch_id text not null unique check(batch_id ~ '^[a-f0-9]{64}$'),
    records_sha256 text not null check(records_sha256 ~ '^[a-f0-9]{64}$'),
    record_count bigint not null check(record_count>=0),
    observed_at timestamptz not null,
    coverage_state text not null check(coverage_state in ('complete','partial')),
    confirmed_at timestamptz not null default now(),
    primary key(manifest_id,family),
    check((previous_manifest_id is null)=(previous_sha256 is null)),
    check(previous_manifest_id is distinct from manifest_id),
    check(previous_manifest_id is not null or (record_count=0 and coverage_state='partial'))
);
alter table public.ad_snapshot_history_confirmations owner to adlog_storage_owner;
create index ad_snapshot_history_window on public.ad_snapshot_history_confirmations(domain_id,family,observed_at);
create index ad_snapshot_history_predecessor on public.ad_snapshot_history_confirmations(previous_manifest_id,family);
revoke all on public.ad_snapshot_history_confirmations from public;
grant select,insert on public.ad_snapshot_history_confirmations to adlog_user;

create function public.ad_snapshot_history_confirmation_guard_v165() returns trigger
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
    select m.manifest_id into expected_previous from public.ad_snapshot_manifests m
    where m.domain_id=new.domain_id and m.slot_start_utc<new.observed_at
    order by m.slot_start_utc desc limit 1;
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
create trigger ad_snapshot_history_confirmation_insert before insert on public.ad_snapshot_history_confirmations
for each row execute function public.ad_snapshot_history_confirmation_guard_v165();
create trigger ad_snapshot_history_confirmation_immutable before update or delete on public.ad_snapshot_history_confirmations
for each row execute function public.ad_snapshot_history_confirmation_guard_v165();
create trigger ad_snapshot_history_confirmation_no_truncate before truncate on public.ad_snapshot_history_confirmations
for each statement execute function public.ad_snapshot_history_confirmation_guard_v165();

create procedure public.expire_ad_snapshot_confirmed_ring_v165(p_manifest_id uuid)
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
    -- Verify each pair before either side can be discarded, including the pair
    -- whose old side expires while its new side stays in the hot ring.
    if exists(select 1 from public.ad_snapshot_manifests m
        cross join unnest(array['users_v2','computers_v6','gpo_v2']) as f(family)
        where m.domain_id=anchor_domain and not exists(
            select 1 from public.ad_snapshot_history_confirmations h
            join public.ad_snapshot_manifest_sources s on s.manifest_id=m.manifest_id and s.family=f.family
            where h.manifest_id=m.manifest_id and h.family=f.family and h.domain_id=m.domain_id
              and h.source_sha256=encode(s.payload_sha256,'hex')
              and not exists(select 1 from public.ad_snapshot_manifests prior
                  where prior.manifest_id=(select p.manifest_id from public.ad_snapshot_manifests p
                      where p.domain_id=m.domain_id and p.slot_start_utc<m.slot_start_utc
                      order by p.slot_start_utc desc limit 1)
                    and (h.previous_manifest_id is distinct from prior.manifest_id
                        or not exists(select 1 from public.ad_snapshot_manifest_sources ps
                            where ps.manifest_id=prior.manifest_id and ps.family=f.family
                              and h.previous_sha256=encode(ps.payload_sha256,'hex')))))) then
        raise exception 'AD snapshot expiry refuses unconfirmed snapshots';
    end if;
    -- The old procedure also deletes unbound compatibility snapshots. They
    -- cannot be silently discarded without a preservation receipt.
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
-- Prevent old callers from bypassing the new preservation fence.
revoke all on procedure public.expire_ad_snapshot_seven_day_ring(uuid) from adlog_user;

create function public.expire_ad_snapshot_history_confirmations_v165(p_cutoff timestamptz) returns bigint
language plpgsql security definer set search_path=pg_catalog,public as $$
declare deleted bigint; configured integer;
begin
    if session_user<>'adlog_user' then
        raise exception 'AD history expiry may be called only by adlog_user' using errcode='42501';
    end if;
    -- The Python caller also validates the environment setting. This database
    -- floor prevents a forged cutoff from shortening the configured policy.
    select value::integer into configured from public.platform_settings where key='ad.snapshot_history_days';
    if configured is not null and configured not between 7 and 3650 then
        raise exception 'invalid AD history policy';
    end if;
    if p_cutoff is null or p_cutoff>now()-make_interval(days=>coalesce(configured,7)) then
        raise exception 'AD history expiry cutoff exceeds policy';
    end if;
    perform pg_advisory_xact_lock(hashtext('sli_ad_snapshot_change_history_v1'));
    delete from public.ad_snapshot_history_confirmations h where h.observed_at<p_cutoff
      and not exists(select 1 from public.ad_snapshot_manifests m
          where m.manifest_id=h.manifest_id or m.manifest_id=h.previous_manifest_id);
    get diagnostics deleted=row_count;
    return deleted;
end $$;
alter function public.expire_ad_snapshot_history_confirmations_v165(timestamptz) owner to postgres;
revoke all on function public.expire_ad_snapshot_history_confirmations_v165(timestamptz) from public;
grant execute on function public.expire_ad_snapshot_history_confirmations_v165(timestamptz) to adlog_user;
insert into public.schema_migrations(version,name) values(165,'ad_snapshot_change_history');
commit;
