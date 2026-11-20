begin;

select pg_advisory_xact_lock(hashtext('ad_log_semantic_v2_quarantine_repair_v143'));

do $$
begin
  if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
    raise exception 'migration 143 requires membership in adlog_storage_owner';
  end if;
  if not exists (select 1 from public.schema_migrations where version=142 and name='semantic_processor_version_gate_and_repair') then
    raise exception 'migration 143 requires exact migration 142 semantic_processor_version_gate_and_repair';
  end if;
  if exists (select 1 from public.schema_migrations where version=143 and name is distinct from 'semantic_v2_quarantine_repair') then
    raise exception 'migration version 143 is already owned by another contract';
  end if;
  if exists (select 1 from public.schema_migrations where version=143 and name='semantic_v2_quarantine_repair') then
    if not exists (
      select 1 from pg_constraint constraint_def
      where conrelid='public.semantic_processing_outbox'::regclass
        and conname='semantic_processing_outbox_job_kind_check'
        and lower(regexp_replace(pg_get_constraintdef(constraint_def.oid), E'\\s+', '', 'g'))
            = $jobkind$check((job_kind=any(array['normalize_event'::text,'assemble_action'::text,'semantic_replay'::text,'investigation_context'::text,'semantic_repair'::text,'semantic_v2_quarantine_repair'::text])))$jobkind$
        and (select array_agg(match[1] order by match[1])
             from regexp_matches(pg_get_constraintdef(constraint_def.oid), '''([^'']+)''', 'g') match)
            = array['assemble_action','investigation_context','normalize_event','semantic_repair','semantic_replay','semantic_v2_quarantine_repair']::text[]
    ) then
      raise exception 'migration 143 replay requires exact final v2 repair job kind constraint';
    end if;
  elsif not exists (
    select 1 from pg_constraint constraint_def
    where conrelid='public.semantic_processing_outbox'::regclass
      and conname='semantic_processing_outbox_job_kind_check'
      and lower(regexp_replace(pg_get_constraintdef(constraint_def.oid), E'\\s+', '', 'g'))
          = $jobkind$check((job_kind=any(array['normalize_event'::text,'assemble_action'::text,'semantic_replay'::text,'investigation_context'::text,'semantic_repair'::text])))$jobkind$
      and (select array_agg(match[1] order by match[1])
           from regexp_matches(pg_get_constraintdef(constraint_def.oid), '''([^'']+)''', 'g') match)
          = array['assemble_action','investigation_context','normalize_event','semantic_repair','semantic_replay']::text[]
  ) then
    raise exception 'migration 143 requires exact pre-v2 repair job kind constraint';
  end if;
end $$;

set local role adlog_storage_owner;
do $$ begin
  if not exists (select 1 from public.schema_migrations where version=143 and name='semantic_v2_quarantine_repair') then
    alter table public.semantic_processing_outbox drop constraint semantic_processing_outbox_job_kind_check;
    alter table public.semantic_processing_outbox add constraint semantic_processing_outbox_job_kind_check check (job_kind in ('normalize_event','assemble_action','semantic_replay','investigation_context','semantic_repair','semantic_v2_quarantine_repair'));
  end if;
end $$;

insert into public.schema_migrations(version,name) values (143, 'semantic_v2_quarantine_repair') on conflict(version) do nothing;
commit;
