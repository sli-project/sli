-- Bound historical entity-card reads and restore covering collection-health reads.
-- psql executes this file in autocommit mode, like migration 144: VACUUM must
-- finish before the migration marker is published and cannot run inside BEGIN.
select pg_advisory_lock(hashtext('sli_entity_context_history_reads_v248'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=247 and name='decoy_delivery_context')
       or not exists(select 1 from public.schema_migrations where version=237 and name='entity_context_health')
       or exists(select 1 from public.schema_migrations where version>=248) then
        raise exception 'migration 248 prerequisites failed';
    end if;
end $$;
-- Keep the admin session for runtime-owned AD tables: adlog_user has no
-- CREATE privilege on public. The inbox below has a different storage owner.
set lock_timeout='5s';

-- The old partial indexes cover current versions only. Cards also read closed
-- versions, ordered by current status and the last observation, before LIMIT.
-- IF NOT EXISTS makes retries safe if maintenance fails before registration.
create index if not exists idx_ad_context_entity_history
    on public.ad_context_entity_versions(entity_id,(valid_to_utc is null) desc,last_observed_at_utc desc);
create index if not exists idx_ad_context_relation_source_history
    on public.ad_context_relation_versions(source_entity_id,(valid_to_utc is null) desc,last_observed_at_utc desc);
create index if not exists idx_ad_context_relation_target_history
    on public.ad_context_relation_versions(target_entity_id,(valid_to_utc is null) desc,last_observed_at_utc desc);

analyze public.ad_context_entity_versions;
analyze public.ad_context_relation_versions;
analyze public.ad_context_evidence;

-- Migration 237 rewrote the inbox to add stored generated columns. ANALYZE
-- alone does not restore all-visible pages: without VACUUM the planner reads
-- the wide heap even though the compact covering index already exists.
set role adlog_storage_owner;
vacuum (analyze) public.sli_agent_packet_inbox;

reset role;
reset lock_timeout;
insert into public.schema_migrations(version,name) values(248,'entity_context_history_reads');
select pg_advisory_unlock(hashtext('sli_entity_context_history_reads_v248'));
