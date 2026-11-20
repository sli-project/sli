begin;

select pg_advisory_xact_lock(hashtext('ad_log_semantic_count_then_rule_kind_v137'));

do $$
begin
  if not exists (
    select 1 from public.schema_migrations
    where version = 136 and name = 'investigation_typed_evidence_refs'
  ) then
    raise exception 'migration 137 requires exact migration 136 investigation_typed_evidence_refs';
  end if;
  if exists (
    select 1 from public.schema_migrations
    where version = 137 and name is distinct from 'semantic_count_then_rule_kind'
  ) then
    raise exception 'migration version 137 is already owned by another contract';
  end if;
end
$$;

alter table semantic_correlation_rules
  drop constraint if exists semantic_correlation_rules_rule_kind_check;
alter table semantic_correlation_rules
  add constraint semantic_correlation_rules_rule_kind_check
  check (rule_kind in (
    'action','sequence','all_of','any_of','count','distinct_count','rate',
    'state_equals','state_changed','relationship_added','relationship_removed',
    'graph_path_created','graph_path_removed','metric_threshold','absence',
    'time_condition','entity_classification','count_then'
  ));

insert into public.schema_migrations(version,name)
values (137, 'semantic_count_then_rule_kind')
on conflict(version) do nothing;

commit;
