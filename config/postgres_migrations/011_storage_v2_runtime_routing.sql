-- STORAGE-V2 migration 11: controlled routing state and minimum runtime grants.
-- This migration is NOT part of the initial schema canary; it is applied only by a later routing gate.

begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_storage_v2_migration_11'));

DO $$
BEGIN
    IF NOT EXISTS (select 1 from pg_roles where rolname='adlog_storage_owner') THEN
        RAISE EXCEPTION 'storage owner role is missing; apply storage_v2_roles.sql first';
    END IF;
END
$$;
SET LOCAL ROLE adlog_storage_owner;

DO $$
BEGIN
    IF coalesce((select max(version) from schema_migrations), 0) < 10 THEN
        RAISE EXCEPTION 'storage_v2 migration 11 requires migration 10';
    END IF;
    IF NOT EXISTS (select 1 from pg_roles where rolname='adlog_user') THEN
        RAISE EXCEPTION 'runtime role adlog_user is missing';
    END IF;
    IF NOT EXISTS (select 1 from pg_roles where rolname='adlog_storage_owner') THEN
        RAISE EXCEPTION 'storage owner role is missing';
    END IF;
END
$$;

create table if not exists storage_v2_cutover_state (
    singleton boolean primary key default true check (singleton),
    read_mode text not null default 'v1' check (read_mode in ('v1', 'shadow', 'v2')),
    write_mode text not null default 'v1' check (write_mode in ('v1', 'v1_outbox', 'v2_primary_compat', 'v2')),
    shadow_sample_rate double precision not null default 0.0 check (shadow_sample_rate >= 0 and shadow_sample_rate <= 1),
    archive_root text,
    state_version bigint not null default 1,
    changed_by text not null default current_user,
    changed_at timestamptz not null default now(),
    rollback_note text
);

insert into storage_v2_cutover_state(singleton, read_mode, write_mode, shadow_sample_rate)
values (true, 'v1', 'v1', 0.0)
on conflict(singleton) do nothing;

revoke all on table storage_v2_cutover_state from public;
revoke all on table events_v2_core, event_facts_v2, entities_v2, entity_details_v2, event_entity_link_blocks_v2 from public;
revoke all on event_entity_links_v2 from public;
revoke all on table storage_v2_archive_sets, storage_v2_archive_blocks from public;
revoke all on table storage_v2_outbox, storage_v2_shadow_results from public;

grant select on storage_v2_cutover_state to adlog_user;
grant select on events_v2_core, event_facts_v2, entities_v2, entity_details_v2, event_entity_link_blocks_v2 to adlog_user;
grant select on event_entity_links_v2 to adlog_user;
grant select on storage_v2_provider, storage_v2_channel, storage_v2_computer, storage_v2_keywords,
    storage_v2_domain_name, storage_v2_entity_type, storage_v2_role to adlog_user;
grant references on events_v2_core, entities_v2 to adlog_user;
grant select on storage_v2_archive_sets, storage_v2_archive_blocks to adlog_user;
grant select, insert on storage_v2_outbox to adlog_user;
grant insert on storage_v2_shadow_results to adlog_user;
grant usage, select on sequence storage_v2_outbox_id_seq, storage_v2_shadow_results_id_seq to adlog_user;

alter table storage_v2_cutover_state owner to adlog_storage_owner;

insert into schema_migrations(version, name)
values (11, 'storage_v2_runtime_routing')
on conflict(version) do update set name=excluded.name;

commit;
