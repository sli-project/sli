-- Stage 6S: immutable source-capture continuity provenance.
-- Source-only schema preparation: no collection, runtime, deployment or apply.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_source_capture_continuity_declarations_v88')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 088 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=87 and name='ad_group_membership_warm_facts'
    ) then
        raise exception 'migration 088 requires migration 087';
    end if;
    if exists(select 1 from schema_migrations where version=88) then
        raise exception 'migration 088 version is already recorded';
    end if;
    if to_regclass('raw_log_files') is null
       or to_regclass('collection_runs') is null
       or to_regclass('events_v2_core') is null then
        raise exception 'migration 088 requires raw-file collection and Storage V2 provenance';
    end if;
end
$$;

-- The declaration owner creates foreign keys to canonical collection and
-- Storage V2 provenance.  Those tables remain owned by the application
-- role, so the exact REFERENCES grants are required before the role switch.
grant references on table collection_runs, raw_log_files, servers, log_sources
    to adlog_storage_owner;

alter table collection_channel_state
    add column if not exists channel_generation_identity text;

set local role adlog_storage_owner;

create table source_capture_continuity_declarations (
    id bigserial primary key,
    collection_run_id bigint not null references collection_runs(id),
    raw_log_file_id bigint not null references raw_log_files(id),
    raw_log_sha256 text not null,
    server_id bigint not null references servers(id),
    log_source_id bigint not null references log_sources(id),
    scope_identity text not null,
    descriptor_source text not null,
    descriptor_stream text not null,
    provider_name text not null,
    channel_value text not null,
    channel_generation_identity text not null,
    selector_event_ids jsonb not null,
    query_exhausted boolean not null,
    capture_after_record_id bigint not null,
    capture_latest_record_id bigint not null,
    first_event_record_id bigint not null,
    last_event_record_id bigint not null,
    completeness text not null default 'complete',
    covered_source_events jsonb not null,
    declaration_sha256 text not null,
    recorded_at timestamptz not null default now(),
    constraint source_capture_continuity_scope_bounded
        check (length(scope_identity) between 1 and 512),
    constraint source_capture_continuity_raw_digest
        check (raw_log_sha256 ~ '^[0-9a-f]{64}$'),
    constraint source_capture_continuity_descriptor_bounded
        check (length(descriptor_source) between 1 and 128
           and length(descriptor_stream) between 1 and 128
           and length(provider_name) between 1 and 512
           and length(channel_value) between 1 and 512),
    constraint source_capture_continuity_capture_range
        check (capture_after_record_id >= 0
           and capture_latest_record_id > capture_after_record_id
           -- Compatibility names are covered range endpoints. Exact observed
           -- sparse rows live only in covered_source_events.
           and first_event_record_id = capture_after_record_id + 1
           and last_event_record_id = capture_latest_record_id),
    constraint source_capture_continuity_selector
        check (jsonb_typeof(selector_event_ids) = 'array'
           and jsonb_array_length(selector_event_ids) > 0),
    constraint source_capture_continuity_query_exhausted
        check (query_exhausted is true),
    constraint source_capture_continuity_completeness
        check (completeness = 'complete'),
    constraint source_capture_continuity_covered_events
        check (jsonb_typeof(covered_source_events) = 'array'),
    constraint source_capture_continuity_digest
        check (declaration_sha256 ~ '^[0-9a-f]{64}$'),
    unique (scope_identity, declaration_sha256)
);

create index source_capture_continuity_declarations_scope_idx
    on source_capture_continuity_declarations(
        server_id, log_source_id, descriptor_source, descriptor_stream,
        provider_name, channel_generation_identity,
        first_event_record_id, last_event_record_id
    );

create function source_capture_continuity_declarations_reject_mutation()
returns trigger
language plpgsql
as $$
begin
    raise exception 'source capture continuity declarations are immutable';
end
$$;

create trigger source_capture_continuity_declarations_immutable
before update or delete on source_capture_continuity_declarations
for each row execute function source_capture_continuity_declarations_reject_mutation();

-- The existing importer and lifecycle read boundary use the application
-- connection.  They may append or read an immutable declaration, but may
-- never mutate or remove it.
grant select, insert on table source_capture_continuity_declarations
    to adlog_user;
grant usage, select on sequence source_capture_continuity_declarations_id_seq
    to adlog_user;

insert into schema_migrations(version,name)
values (88,'source_capture_continuity_declarations')
on conflict(version) do update set name=excluded.name;

commit;
