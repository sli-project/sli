-- WR02: projection storage only; no evaluation, collection or access assignment.
begin;
select pg_advisory_xact_lock(hashtext('sli_workstation_overview_projections_v252'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=251 and name='workstation_access')
       or not exists(select 1 from public.schema_migrations where version=209 and name='workstation_protection_state')
       or exists(select 1 from public.schema_migrations where version>=252) then
        raise exception 'migration 252 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;
set local lock_timeout='5s';

-- Stable station IDs survive changes to names, directory links and enrollment.
-- Missing/ambiguous directory associations must never be inferred from a name.
create table sli_plugin_workstations.station_inventory (
    station_id text primary key check(length(trim(station_id)) between 1 and 256),
    entity_id bigint unique check(entity_id>0),
    ad_computer_id bigint unique check(ad_computer_id>0),
    agent_key text unique check(length(trim(agent_key)) between 1 and 256),
    domain_id bigint check(domain_id>0),
    ou_entity_id bigint check(ou_entity_id>0),
    station_type text not null default 'unknown' check(station_type in ('workstation','server','unknown')),
    association_status text not null default 'unlinked' check(association_status in ('unlinked','unique','ambiguous')),
    metadata jsonb not null default '{}' check(jsonb_typeof(metadata)='object' and octet_length(metadata::text)<=32768),
    metadata_observed_at timestamptz,
    quality jsonb not null default '{"status":"not_collected","reasons":[]}'
        check(jsonb_typeof(quality)='object' and coalesce(quality->>'status' in
            ('complete','partial','stale','unavailable','not_collected','denied'),false)
            and coalesce(jsonb_typeof(quality->'reasons')='array',false) and octet_length(quality::text)<=16384),
    revision bigint not null default 1 check(revision>0),
    updated_at timestamptz not null default now(),
    check(entity_id is not null or ad_computer_id is not null or agent_key is not null),
    check(ou_entity_id is null or domain_id is not null),
    check(association_status<>'ambiguous' or (ad_computer_id is null and domain_id is null and ou_entity_id is null))
);
create index workstation_inventory_scope on sli_plugin_workstations.station_inventory(domain_id,ou_entity_id,station_id);

-- Hot list rows never require observation XML or a scan of retained history.
-- Unknown counters remain absent/null in the versioned DTO, never default zero.
create table sli_plugin_workstations.station_summary (
    station_id text primary key references sli_plugin_workstations.station_inventory(station_id),
    last_interactive_login jsonb not null default '{}'
        check(jsonb_typeof(last_interactive_login)='object' and octet_length(last_interactive_login::text)<=8192),
    health jsonb not null default '{}' check(jsonb_typeof(health)='object' and octet_length(health::text)<=16384),
    protection jsonb not null default '{}' check(jsonb_typeof(protection)='object' and octet_length(protection::text)<=16384),
    counters jsonb not null default '{}' check(jsonb_typeof(counters)='object' and octet_length(counters::text)<=8192),
    quality jsonb not null default '{"status":"not_collected","reasons":[]}'
        check(jsonb_typeof(quality)='object' and coalesce(quality->>'status' in
            ('complete','partial','stale','unavailable','not_collected','denied'),false)
            and coalesce(jsonb_typeof(quality->'reasons')='array',false) and octet_length(quality::text)<=16384),
    revision bigint not null default 1 check(revision>0),
    as_of_utc timestamptz not null,
    updated_at timestamptz not null default now()
);

create table sli_plugin_workstations.check_findings (
    id text primary key check(id ~ '^[a-f0-9]{64}$'),
    station_id text not null references sli_plugin_workstations.station_inventory(station_id),
    check_id text not null check(check_id in ('C01','C02','C03','C04','C05','C06','C07','C08','C09','C10')),
    rule_version integer not null check(rule_version>0),
    subject_id text check(length(trim(subject_id)) between 1 and 256),
    subject_ref jsonb not null default '{}' check(jsonb_typeof(subject_ref)='object' and octet_length(subject_ref::text)<=8192),
    episode_id text not null check(episode_id ~ '^[a-f0-9]{64}$'),
    revision bigint not null default 1 check(revision>0),
    condition_sha256 text not null check(condition_sha256 ~ '^[a-f0-9]{64}$'),
    status text not null check(status in ('active','resolved')),
    severity text not null check(severity in ('high','medium','low')),
    fact_at timestamptz,
    first_detected_at timestamptz not null,
    last_observed_at timestamptz not null,
    materially_changed_at timestamptz not null,
    resolved_at timestamptz,
    reason_code text not null check(length(trim(reason_code)) between 1 and 128),
    reason_params jsonb not null default '{}' check(jsonb_typeof(reason_params)='object' and octet_length(reason_params::text)<=16384),
    quality jsonb not null default '{"status":"not_collected","reasons":[]}'
        check(jsonb_typeof(quality)='object' and coalesce(quality->>'status' in
            ('complete','partial','stale','unavailable','not_collected','denied'),false)
            and coalesce(jsonb_typeof(quality->'reasons')='array',false) and octet_length(quality::text)<=16384),
    -- Typed observation/core-event/snapshot refs; no FK to expiring evidence.
    evidence_refs jsonb not null default '[]' check(jsonb_typeof(evidence_refs)='array' and octet_length(evidence_refs::text)<=65536),
    constraint workstation_finding_episode unique nulls not distinct(check_id,rule_version,station_id,subject_id,episode_id),
    check(materially_changed_at>=first_detected_at),
    check((status='active' and resolved_at is null)
        or (status='resolved' and resolved_at is not null and resolved_at>=first_detected_at))
);
create index workstation_findings_check on sli_plugin_workstations.check_findings(check_id,status,severity,station_id,id);
create index workstation_findings_station on sli_plugin_workstations.check_findings(station_id,status,fact_at desc,id desc);
create index workstation_findings_detected on sli_plugin_workstations.check_findings(check_id,first_detected_at desc,id desc);

-- Append-only runtime history. Actor is independent of the last login/subject.
create table sli_plugin_workstations.station_changes (
    id text primary key check(id ~ '^[a-f0-9]{64}$'),
    station_id text not null references sli_plugin_workstations.station_inventory(station_id),
    change_kind text not null check(length(trim(change_kind)) between 1 and 128),
    event_at timestamptz,
    detected_at timestamptz not null,
    actor_ref jsonb not null default '{}' check(jsonb_typeof(actor_ref)='object' and octet_length(actor_ref::text)<=8192),
    subject_ref jsonb not null default '{}' check(jsonb_typeof(subject_ref)='object' and octet_length(subject_ref::text)<=8192),
    reason_code text not null check(length(trim(reason_code)) between 1 and 128),
    reason_params jsonb not null default '{}' check(jsonb_typeof(reason_params)='object' and octet_length(reason_params::text)<=16384),
    quality jsonb not null default '{"status":"not_collected","reasons":[]}'
        check(jsonb_typeof(quality)='object' and coalesce(quality->>'status' in
            ('complete','partial','stale','unavailable','not_collected','denied'),false)
            and coalesce(jsonb_typeof(quality->'reasons')='array',false) and octet_length(quality::text)<=16384),
    evidence_refs jsonb not null default '[]' check(jsonb_typeof(evidence_refs)='array' and octet_length(evidence_refs::text)<=65536)
);
create index workstation_changes_station on sli_plugin_workstations.station_changes(station_id,(coalesce(event_at,detected_at)) desc,id desc);
create index workstation_changes_time on sli_plugin_workstations.station_changes((coalesce(event_at,detected_at)) desc,id desc);

-- WR05 owns durable scheduling/replay. This position is a typed committed
-- import/revision fence, NOT the lexicographic maximum observation hash.
create table sli_plugin_workstations.projection_checkpoints (
    projector_key text not null check(length(trim(projector_key)) between 1 and 128),
    partition_key text not null check(length(trim(partition_key)) between 1 and 256),
    projection_version integer not null check(projection_version>0),
    committed_position jsonb not null default '{}'
        check(jsonb_typeof(committed_position)='object' and octet_length(committed_position::text)<=8192),
    revision bigint not null default 1 check(revision>0),
    updated_at timestamptz not null default now(),
    primary key(projector_key,partition_key)
);
revoke all on sli_plugin_workstations.station_inventory,sli_plugin_workstations.station_summary,
    sli_plugin_workstations.check_findings,sli_plugin_workstations.station_changes,
    sli_plugin_workstations.projection_checkpoints from public,adlog_user;
grant select,insert,update on sli_plugin_workstations.station_inventory,sli_plugin_workstations.station_summary,
    sli_plugin_workstations.check_findings,sli_plugin_workstations.projection_checkpoints to adlog_user;
grant select,insert on sli_plugin_workstations.station_changes to adlog_user;
reset role;
insert into public.schema_migrations(version,name) values(252,'workstation_overview_projections');
commit;
