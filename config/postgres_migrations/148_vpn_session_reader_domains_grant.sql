-- Migration 148 — column grant on domains for the VPN session reader role.
--
-- Defect: migration 062 granted select(id, fqdn) on domains to
-- adlog_vpn_session_reader_owner, but the squashed baseline (144) does not
-- contain that grant. On a clean install the view radius_vpn_session_coverage_v1
-- fails with "permission denied for table domains" and the VPN connections
-- report cannot read its source. The grant is idempotent: installations that
-- went through 062 already have it.

begin;

select pg_advisory_xact_lock(hashtext('ad_log_vpn_session_reader_domains_grant_v148'));

do $$
begin
  if not exists (
    select 1 from public.schema_migrations
    where version = 147 and name = 'domain_controller_targets'
  ) then
    raise exception 'migration 148 requires exact migration 147 domain_controller_targets';
  end if;
  if exists (
    select 1 from public.schema_migrations
    where version = 148 and name is distinct from 'vpn_session_reader_domains_grant'
  ) then
    raise exception 'migration version 148 is already owned by another contract';
  end if;
  if to_regrole('adlog_vpn_session_reader_owner') is null then
    raise exception 'migration 148 requires role adlog_vpn_session_reader_owner';
  end if;
end
$$;

grant select (id, fqdn) on public.domains to adlog_vpn_session_reader_owner;

insert into schema_migrations(version, name)
values (148, 'vpn_session_reader_domains_grant')
on conflict(version) do update set name=excluded.name;

commit;
