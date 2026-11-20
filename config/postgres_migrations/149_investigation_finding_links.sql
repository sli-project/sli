-- Migration 149 — link between a problem (finding) and an investigation case.
--
-- Owner decision 2026-10-02: an analyst opens an investigation from the
-- problems queue or attaches the problem to an existing open case. A finding
-- belongs to at most one case (unique finding_id); a case may hold many
-- findings. Rows are never updated or deleted by the application, so the
-- runtime role gets select and insert only. Foreign keys restrict deletion of
-- both sides while a link exists.
--
-- Additive: one new table, no change to existing rows.

begin;

select pg_advisory_xact_lock(hashtext('ad_log_investigation_finding_links_v149'));

do $$
begin
  if not exists (
    select 1 from public.schema_migrations
    where version = 148 and name = 'vpn_session_reader_domains_grant'
  ) then
    raise exception 'migration 149 requires exact migration 148 vpn_session_reader_domains_grant';
  end if;
  if exists (
    select 1 from public.schema_migrations
    where version = 149 and name is distinct from 'investigation_finding_links'
  ) then
    raise exception 'migration version 149 is already owned by another contract';
  end if;
end
$$;

create table if not exists public.investigation_finding_links (
    investigation_id bigint not null references public.investigations(id) on delete restrict,
    finding_id bigint not null references public.findings(id) on delete restrict,
    linked_by text not null check (length(linked_by) between 1 and 256),
    linked_at timestamptz not null default now(),
    primary key (investigation_id, finding_id),
    constraint investigation_finding_links_finding_key unique (finding_id)
);

alter table public.investigation_finding_links owner to adlog_user;

grant select, insert on public.investigation_finding_links to adlog_user;

insert into schema_migrations(version, name)
values (149, 'investigation_finding_links')
on conflict(version) do update set name=excluded.name;

commit;
