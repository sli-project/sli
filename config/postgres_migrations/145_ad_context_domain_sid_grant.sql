-- Migration 145 — let the AD Context import record the domain SID once.
--
-- server/ad_context/repository.py::_resolve_domain sets domains.domain_sid on
-- the first AD Context import for a domain whose SID is still unknown
-- ("update domains set domain_sid=... where ... and domain_sid is null").
-- The import runs as adlog_context_worker, which until now had only SELECT on
-- domains (migration 034), so a clean installation failed its first AD
-- Context import with "permission denied for table domains". Existing
-- installations already have the SID and never reach the UPDATE.
--
-- Column-level and additive: only UPDATE(domain_sid), no other column, no
-- table-wide UPDATE, no INSERT/DELETE.

begin;

select pg_advisory_xact_lock(hashtext('ad_log_ad_context_domain_sid_grant_v145'));

do $$
begin
  if not exists (
    select 1 from public.schema_migrations
    where version = 144 and name = 'ad_context_evidence_record_key_index'
  ) then
    raise exception 'migration 145 requires exact migration 144 ad_context_evidence_record_key_index';
  end if;
  if exists (
    select 1 from public.schema_migrations
    where version = 145 and name is distinct from 'ad_context_domain_sid_grant'
  ) then
    raise exception 'migration version 145 is already owned by another contract';
  end if;
  if to_regrole('adlog_context_worker') is null then
    raise exception 'migration 145 requires runtime role adlog_context_worker';
  end if;
  if has_table_privilege('adlog_context_worker', 'public.domains', 'UPDATE') then
    raise exception 'migration 145 found an unexpected table-wide UPDATE on domains';
  end if;
end
$$;

grant update (domain_sid) on public.domains to adlog_context_worker;

insert into schema_migrations(version, name)
values (145, 'ad_context_domain_sid_grant')
on conflict(version) do update set name=excluded.name;

commit;
