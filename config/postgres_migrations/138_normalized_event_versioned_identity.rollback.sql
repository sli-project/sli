begin;

select pg_advisory_xact_lock(hashtext('ad_log_normalized_event_versioned_identity_v138'));

do $$
begin
  if not exists (
    select 1 from public.schema_migrations
    where version = 138 and name = 'normalized_event_versioned_identity'
  ) then
    raise exception 'migration 138 rollback requires exact marker';
  end if;
  if exists (
    select 1
    from public.normalized_events
    group by source_event_id, semantic_contract_version, semantic_sha256
    having count(*) > 1
  ) then
    raise exception 'migration 138 rollback refuses cross-version normalized semantic hash collisions';
  end if;
end
$$;

alter table public.normalized_events
  add constraint normalized_events_source_event_id_semantic_contract_versio_key1
  unique (source_event_id, semantic_contract_version, semantic_sha256);

delete from public.schema_migrations
where version = 138 and name = 'normalized_event_versioned_identity';

commit;
