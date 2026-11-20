-- STORAGE-V2 migration 12: rebind retained application references to V2 identities.
-- SOURCE ONLY.  This is forbidden until full backfill, V2 runtime shadow and
-- controlled cutover gates have all passed.  It does not delete any V1 data.

begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_storage_v2_migration_12'));
DO $$
BEGIN
    IF NOT pg_has_role(session_user, 'adlog_user', 'MEMBER') THEN
        RAISE EXCEPTION 'migration 12 requires the non-login migrator to inherit adlog_user';
    END IF;
END
$$;
SET LOCAL ROLE adlog_storage_owner;

DO $$
DECLARE
    routing record;
BEGIN
    IF coalesce((select max(version) from schema_migrations), 0) < 11 THEN
        RAISE EXCEPTION 'storage_v2 migration 12 requires migration 11';
    END IF;
    select * into routing from storage_v2_cutover_state where singleton=true;
    IF routing.read_mode <> 'v2' or routing.write_mode not in ('v2_primary_compat', 'v2') THEN
        RAISE EXCEPTION 'reference cutover requires V2 read and V2-primary write routing';
    END IF;
    IF exists (
        select 1 from storage_v2_backfill_checkpoints
        where worker_name not like 'outbox-%'
          and (state <> 'completed' or last_verified_event_id <> high_watermark_event_id)
    ) THEN
        RAISE EXCEPTION 'reference cutover requires completed verified backfill checkpoints';
    END IF;
    IF exists (
        select 1 from storage_v2_outbox
        where state not in ('completed', 'quarantined')
    ) THEN
        RAISE EXCEPTION 'reference cutover forbidden while outbox work is active';
    END IF;
END
$$;

-- Completeness validation and retained-table DDL use the runtime owner,
-- which can read both the retained V1 tables and the dark V2 identities.
SET LOCAL ROLE adlog_user;

DO $$
DECLARE
    missing_rows bigint;
    out_of_range bigint;
BEGIN
    select count(*) into out_of_range from (
        select source_event_id as id from event_links
        union all select target_event_id from event_links
        union all select entity_id from entity_states
        union all select evidence_event_id from entity_states where evidence_event_id is not null
        union all select primary_event_id from detections where primary_event_id is not null
        union all select event_id from finding_evidence
        union all select entity_id from finding_entities where entity_id is not null
    ) retained where id <= 0 or id > 2147483647;
    IF out_of_range <> 0 THEN
        RAISE EXCEPTION 'storage_v2 int32 identity capacity exceeded by % retained references', out_of_range;
    END IF;
    select count(*) into missing_rows from events e
      left join events_v2_core v2 on v2.id=e.id where v2.id is null;
    IF missing_rows <> 0 THEN
        RAISE EXCEPTION 'reference cutover missing % V2 event identities', missing_rows;
    END IF;
    select count(*) into missing_rows from (
        select source_event_id as id from event_links
        union select target_event_id from event_links
        union select evidence_event_id from entity_states where evidence_event_id is not null
        union select primary_event_id from detections where primary_event_id is not null
        union select event_id from finding_evidence
    ) refs left join events_v2_core v2 on v2.id=refs.id where v2.id is null;
    IF missing_rows <> 0 THEN
        RAISE EXCEPTION 'retained tables reference % events absent from V2', missing_rows;
    END IF;
    select count(*) into missing_rows from (
        select entity_id as id from entity_states
        union select entity_id from finding_entities where entity_id is not null
    ) refs left join entities_v2 v2 on v2.id=refs.id where v2.id is null;
    IF missing_rows <> 0 THEN
        RAISE EXCEPTION 'retained tables reference % entities absent from V2', missing_rows;
    END IF;
END
$$;

alter table event_links drop constraint if exists event_links_source_event_id_fkey;
alter table event_links drop constraint if exists event_links_target_event_id_fkey;
alter table entity_states drop constraint if exists entity_states_entity_id_fkey;
alter table entity_states drop constraint if exists entity_states_evidence_event_id_fkey;
alter table detections drop constraint if exists detections_primary_event_id_fkey;
alter table finding_evidence drop constraint if exists finding_evidence_event_id_fkey;
alter table finding_entities drop constraint if exists finding_entities_entity_id_fkey;

alter table event_links add constraint event_links_source_event_id_v2_fkey
    foreign key (source_event_id) references events_v2_core(id) not valid;
alter table event_links add constraint event_links_target_event_id_v2_fkey
    foreign key (target_event_id) references events_v2_core(id) not valid;
alter table entity_states add constraint entity_states_entity_id_v2_fkey
    foreign key (entity_id) references entities_v2(id) not valid;
alter table entity_states add constraint entity_states_evidence_event_id_v2_fkey
    foreign key (evidence_event_id) references events_v2_core(id) not valid;
alter table detections add constraint detections_primary_event_id_v2_fkey
    foreign key (primary_event_id) references events_v2_core(id) not valid;
alter table finding_evidence add constraint finding_evidence_event_id_v2_fkey
    foreign key (event_id) references events_v2_core(id) not valid;
alter table finding_entities add constraint finding_entities_entity_id_v2_fkey
    foreign key (entity_id) references entities_v2(id) not valid;

alter table event_links validate constraint event_links_source_event_id_v2_fkey;
alter table event_links validate constraint event_links_target_event_id_v2_fkey;
alter table entity_states validate constraint entity_states_entity_id_v2_fkey;
alter table entity_states validate constraint entity_states_evidence_event_id_v2_fkey;
alter table detections validate constraint detections_primary_event_id_v2_fkey;
alter table finding_evidence validate constraint finding_evidence_event_id_v2_fkey;
alter table finding_entities validate constraint finding_entities_entity_id_v2_fkey;

SET LOCAL ROLE adlog_storage_owner;
insert into schema_migrations(version, name)
values (12, 'storage_v2_external_reference_cutover')
on conflict(version) do update set name=excluded.name;

commit;
