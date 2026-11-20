-- Roll back migration 12 only while the complete V1 identity tables still exist.
begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_storage_v2_migration_12'));
DO $$
BEGIN
    IF NOT pg_has_role(session_user, 'adlog_user', 'MEMBER') THEN
        RAISE EXCEPTION 'migration 12 rollback requires the non-login migrator to inherit adlog_user';
    END IF;
END
$$;
SET LOCAL ROLE adlog_user;

DO $$
DECLARE
    missing_rows bigint;
BEGIN
    IF to_regclass('public.events') is null or to_regclass('public.observed_entities') is null THEN
        RAISE EXCEPTION 'migration 12 rollback requires retained V1 identity tables';
    END IF;
    select count(*) into missing_rows from events_v2_core v2
      left join events v1 on v1.id=v2.id where v1.id is null;
    IF missing_rows <> 0 THEN
        RAISE EXCEPTION 'migration 12 rollback missing % V1 event identities', missing_rows;
    END IF;
    select count(*) into missing_rows from entities_v2 v2
      left join observed_entities v1 on v1.id=v2.id where v1.id is null;
    IF missing_rows <> 0 THEN
        RAISE EXCEPTION 'migration 12 rollback missing % V1 entity identities', missing_rows;
    END IF;
END
$$;

alter table event_links drop constraint if exists event_links_source_event_id_v2_fkey;
alter table event_links drop constraint if exists event_links_target_event_id_v2_fkey;
alter table entity_states drop constraint if exists entity_states_entity_id_v2_fkey;
alter table entity_states drop constraint if exists entity_states_evidence_event_id_v2_fkey;
alter table detections drop constraint if exists detections_primary_event_id_v2_fkey;
alter table finding_evidence drop constraint if exists finding_evidence_event_id_v2_fkey;
alter table finding_entities drop constraint if exists finding_entities_entity_id_v2_fkey;

alter table event_links add constraint event_links_source_event_id_fkey
    foreign key (source_event_id) references events(id) not valid;
alter table event_links add constraint event_links_target_event_id_fkey
    foreign key (target_event_id) references events(id) not valid;
alter table entity_states add constraint entity_states_entity_id_fkey
    foreign key (entity_id) references observed_entities(id) not valid;
alter table entity_states add constraint entity_states_evidence_event_id_fkey
    foreign key (evidence_event_id) references events(id) not valid;
alter table detections add constraint detections_primary_event_id_fkey
    foreign key (primary_event_id) references events(id) not valid;
alter table finding_evidence add constraint finding_evidence_event_id_fkey
    foreign key (event_id) references events(id) not valid;
alter table finding_entities add constraint finding_entities_entity_id_fkey
    foreign key (entity_id) references observed_entities(id) not valid;

alter table event_links validate constraint event_links_source_event_id_fkey;
alter table event_links validate constraint event_links_target_event_id_fkey;
alter table entity_states validate constraint entity_states_entity_id_fkey;
alter table entity_states validate constraint entity_states_evidence_event_id_fkey;
alter table detections validate constraint detections_primary_event_id_fkey;
alter table finding_evidence validate constraint finding_evidence_event_id_fkey;
alter table finding_entities validate constraint finding_entities_entity_id_fkey;

SET LOCAL ROLE adlog_storage_owner;
update storage_v2_cutover_state
set read_mode='v1',
    write_mode='v1',
    shadow_sample_rate=0.0,
    state_version=state_version + 1,
    changed_by=current_user,
    changed_at=now(),
    rollback_note='migration 12 rollback restored V1 references and routing'
where singleton=true;
delete from schema_migrations where version=12;
commit;
