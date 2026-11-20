-- Roll back SEMANTIC-PERSISTENCE-1 only while its durable tables are empty.
-- Dropping the new columns after processing data would destroy semantic identity.

begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_semantic_persistence_contract_v25'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'rollback 025 requires membership in adlog_storage_owner';
    end if;
    if exists (select 1 from normalized_events)
       or exists (select 1 from canonical_actions)
       or exists (select 1 from semantic_processing_outbox) then
        raise exception 'rollback 025 refused: semantic persistence data exists';
    end if;
end
$$;

set local role adlog_storage_owner;

drop index if exists idx_semantic_outbox_partition_claim;
drop index if exists idx_normalized_events_semantic_time;

alter table semantic_processing_outbox
    drop constraint if exists semantic_processing_outbox_partition_bounded,
    drop column if exists emitted_at,
    drop column if exists occurred_at_utc,
    drop column if exists partition_key,
    drop column if exists domain_id,
    drop column if exists source_id;

alter table canonical_actions
    drop constraint if exists canonical_actions_dedup_identity_unique,
    drop constraint if exists canonical_actions_dedup_key_length,
    drop column if exists canonical_deduplication_key;

alter table canonical_action_evidence
    drop constraint if exists canonical_action_evidence_entity_role_check;

alter table canonical_action_evidence
    add constraint canonical_action_evidence_entity_role_check
    check (
        entity_role is null or entity_role in (
            'actor','session_principal','affected','target','container','source','context'
        )
    );

alter table normalized_events
    drop constraint if exists normalized_events_roles_object,
    drop constraint if exists normalized_events_semantic_type_bounded,
    drop column if exists roles_json,
    drop column if exists source_ingested_at,
    drop column if exists occurred_at_utc,
    drop column if exists semantic_type;

delete from schema_migrations
where version=25 and name='semantic_persistence_contract';

commit;
