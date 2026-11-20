begin;

select pg_advisory_xact_lock(hashtext('ad_log_investigation_typed_evidence_refs_v136'));

do $$
begin
  if not exists (
    select 1 from public.schema_migrations
    where version = 135 and name = 'semantic_cross_dc_partitions'
  ) then
    raise exception 'migration 136 requires exact migration 135 semantic_cross_dc_partitions';
  end if;
  if exists (
    select 1 from public.schema_migrations
    where version = 136 and name is distinct from 'investigation_typed_evidence_refs'
  ) then
    raise exception 'migration version 136 is already owned by another contract';
  end if;
end
$$;

create table if not exists public.investigation_evidence_refs (
  investigation_id bigint not null references public.investigations(id) on delete restrict,
  evidence_kind text not null check (evidence_kind in ('vpn_accounting_session')),
  source_domain_id bigint not null references public.domains(id) on delete restrict,
  reference_id text not null check (length(reference_id) between 1 and 256),
  relation_status text not null default 'confirmed'
    check (relation_status in ('confirmed','excluded')),
  added_by text not null check (length(added_by) between 1 and 200),
  added_at timestamptz not null default now(),
  primary key (investigation_id,evidence_kind,source_domain_id,reference_id)
);

create index if not exists investigation_evidence_refs_domain_idx
  on public.investigation_evidence_refs(source_domain_id,investigation_id);

comment on table public.investigation_evidence_refs is
  'Typed immutable evidence references; never substitutes a non-Windows source for event_db_id';

insert into public.schema_migrations(version,name)
values (136, 'investigation_typed_evidence_refs')
on conflict(version) do nothing;

commit;
