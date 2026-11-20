begin;

select pg_advisory_xact_lock(hashtext('ad_log_normalized_event_versioned_identity_v138'));

do $$
begin
  if not exists (
    select 1 from public.schema_migrations
    where version = 137 and name = 'semantic_count_then_rule_kind'
  ) then
    raise exception 'migration 138 requires exact migration 137 semantic_count_then_rule_kind';
  end if;
  if exists (
    select 1 from public.schema_migrations
    where version = 138 and name is distinct from 'normalized_event_versioned_identity'
  ) then
    raise exception 'migration version 138 is already owned by another contract';
  end if;
  if not exists (
    select 1 from pg_constraint constraint_def
    where constraint_def.conrelid = 'public.normalized_events'::regclass
      and constraint_def.contype = 'u'
      and pg_get_constraintdef(constraint_def.oid) =
          'UNIQUE (source_event_id, semantic_contract_version, normalizer_id, normalizer_version)'
  ) then
    raise exception 'migration 138 requires versioned normalized-events unique constraint';
  end if;
end
$$;

alter table public.normalized_events
  drop constraint if exists normalized_events_source_event_id_semantic_contract_versio_key1;

do $$
begin
  if exists (
    select 1 from pg_constraint constraint_def
    where constraint_def.conrelid = 'public.normalized_events'::regclass
      and constraint_def.conname = 'normalized_events_source_event_id_semantic_contract_versio_key1'
  ) then
    raise exception 'migration 138 failed to remove obsolete cross-version semantic hash unique constraint';
  end if;
end
$$;

insert into public.schema_migrations(version,name)
values (138, 'normalized_event_versioned_identity')
on conflict(version) do nothing;

commit;
