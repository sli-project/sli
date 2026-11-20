-- Rollback is allowed only before the first immutable merge/replay evidence.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_entity_identity_merge_r7_v68')
);

do $$
begin
    if exists (select 1 from entity_identity_merges_v2)
       or exists (select 1 from entity_identity_merge_events_v2)
       or exists (select 1 from entity_identity_semantic_replays_v2)
       or exists (select 1 from entity_identity_scenario_supersessions_v2)
       or exists (select 1 from entity_identity_finding_supersessions_v2) then
        raise exception 'migration 068 rollback blocked by immutable R7 evidence';
    end if;
end
$$;

set local role adlog_storage_owner;

drop view if exists entities_v2_active;
drop view if exists findings_active;
drop trigger if exists trg_event_entity_link_block_reject_merged
    on event_entity_link_blocks_v2;
drop function if exists reject_merged_entity_link_block();
drop trigger if exists trg_entity_identity_merge_flat_graph
    on entity_identity_merges_v2;
drop trigger if exists trg_entity_identity_scenario_supersessions_immutable
    on entity_identity_scenario_supersessions_v2;
drop trigger if exists trg_entity_identity_finding_supersessions_immutable
    on entity_identity_finding_supersessions_v2;
drop trigger if exists trg_entity_identity_semantic_replays_immutable
    on entity_identity_semantic_replays_v2;
drop trigger if exists trg_entity_identity_merge_events_immutable
    on entity_identity_merge_events_v2;
drop trigger if exists trg_entity_identity_merges_immutable
    on entity_identity_merges_v2;
drop function if exists validate_entity_identity_merge_flat_graph();
drop function if exists enforce_entity_identity_merge_immutability();
drop function if exists resolve_entity_identity_v2(integer);
drop table if exists entity_identity_finding_supersessions_v2;
drop table if exists entity_identity_scenario_supersessions_v2;
drop table if exists entity_identity_semantic_replays_v2;
drop table if exists entity_identity_merge_events_v2;
drop table if exists entity_identity_merges_v2;

revoke select on table findings from adlog_storage_owner;

delete from schema_migrations
where version=68 and name='entity_identity_merge_r7';

commit;
