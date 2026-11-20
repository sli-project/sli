select pg_advisory_xact_lock(hashtext('ad_log_reports_ad_snapshot_manifest_foundation'));

do $$ begin
  if exists(
    select 1 from schema_migrations
    where version=121
      and name is distinct from 'ad_snapshot_manifest_foundation'
  ) then
    raise exception 'migration 121 is already registered with a different name';
  end if;
end $$;

do $$ begin
  if not exists(
    select 1 from schema_migrations
    where version=120 and name='gpo_v2_replaces_legacy_catalog'
  ) then
    raise exception 'AD snapshot manifest foundation requires migration 120';
  end if;
end $$;

create table if not exists ad_snapshot_manifests (
  manifest_id uuid primary key,
  domain_id bigint not null references domains(id) on delete restrict,
  domain_sid text not null check(length(btrim(domain_sid))>0),
  domain_dns text not null check(length(btrim(domain_dns))>0),
  slot_start_utc timestamptz not null,
  assembled_at_utc timestamptz not null,
  contract_version text not null check(contract_version='sli.ad-snapshot-manifest/1.0'),
  coverage_state text not null check(coverage_state in ('complete','partial')),
  manifest_sha256 bytea not null check(octet_length(manifest_sha256)=32),
  created_at timestamptz not null default now(),
  unique(domain_id, slot_start_utc, contract_version),
  check(slot_start_utc=date_trunc('day',slot_start_utc)
        or slot_start_utc=date_trunc('day',slot_start_utc)+interval '12 hours'),
  check(assembled_at_utc>=slot_start_utc)
);

create table if not exists ad_snapshot_manifest_sources (
  manifest_id uuid not null references ad_snapshot_manifests(manifest_id) on delete restrict,
  family text not null check(family in (
    'ad_context_base','ad_privileged_membership','ad_vpn_membership',
    'ad_domain_posture','ad_domain_health','ad_gpo_governance',
    'users_v2','computers_v6','gpo_v2'
  )),
  contract_id text not null check(length(btrim(contract_id))>0),
  source_id text not null check(length(btrim(source_id))>0),
  observed_at_utc timestamptz not null,
  source_state text not null check(source_state in ('complete','partial','failed')),
  payload_sha256 bytea not null check(octet_length(payload_sha256)=32),
  reason_code text,
  primary key(manifest_id,family),
  check((source_state='complete' and reason_code is null)
        or (source_state<>'complete' and reason_code is not null
            and length(btrim(reason_code))>0))
);

create or replace function ad_snapshot_manifest_reject_mutation()
returns trigger language plpgsql as $$
begin
  raise exception 'AD snapshot manifests are immutable';
end $$;

drop trigger if exists trg_ad_snapshot_manifests_immutable on ad_snapshot_manifests;
create trigger trg_ad_snapshot_manifests_immutable
before update or delete or truncate on ad_snapshot_manifests
for each statement execute function ad_snapshot_manifest_reject_mutation();

drop trigger if exists trg_ad_snapshot_manifest_sources_immutable on ad_snapshot_manifest_sources;
create trigger trg_ad_snapshot_manifest_sources_immutable
before update or delete or truncate on ad_snapshot_manifest_sources
for each statement execute function ad_snapshot_manifest_reject_mutation();

create index if not exists idx_ad_snapshot_manifests_slot
  on ad_snapshot_manifests(domain_id,slot_start_utc desc,manifest_id);

create table if not exists ad_snapshot_projection_receipts (
  manifest_id uuid not null references ad_snapshot_manifests(manifest_id) on delete restrict,
  projection_key text not null check(projection_key in ('ad.users.v2','ad.computers.v6','ad.gpo.v2','ad.state')),
  projection_version integer not null check(projection_version=1),
  status text not null check(status in ('pending','running','completed','failed')),
  attempt_count integer not null default 0 check(attempt_count between 0 and 16),
  lease_owner text,
  lease_expires_at timestamptz,
  input_sha256 bytea check(input_sha256 is null or octet_length(input_sha256)=32),
  output_sha256 bytea check(output_sha256 is null or octet_length(output_sha256)=32),
  output_identity text,
  last_error text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key(manifest_id,projection_key,projection_version),
  check((status='running')=(lease_owner is not null and lease_expires_at is not null))
);

create index if not exists idx_ad_snapshot_projection_receipts_claim
  on ad_snapshot_projection_receipts(status,lease_expires_at,attempt_count,created_at);

revoke all on ad_snapshot_manifests from public;
revoke all on ad_snapshot_manifest_sources from public;
revoke all on ad_snapshot_projection_receipts from public;

do $$ begin
  if exists(select 1 from pg_roles where rolname='adlog_context_worker') then
    execute 'grant select, insert on ad_snapshot_manifests to adlog_context_worker';
    execute 'grant select, insert on ad_snapshot_manifest_sources to adlog_context_worker';
    execute 'grant select, insert, update on ad_snapshot_projection_receipts to adlog_context_worker';
  end if;
end $$;

insert into schema_migrations(version,name)
values(121,'ad_snapshot_manifest_foundation')
on conflict(version) do nothing;
