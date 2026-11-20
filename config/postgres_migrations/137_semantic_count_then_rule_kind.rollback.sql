begin;

select pg_advisory_xact_lock(hashtext('ad_log_semantic_count_then_rule_kind_v137'));

do $$
begin
  if not exists (
    select 1 from public.schema_migrations
    where version = 137 and name = 'semantic_count_then_rule_kind'
  ) then
    raise exception 'migration 137 rollback requires exact marker';
  end if;
  if exists (
    select 1 from semantic_correlation_rules where rule_kind = 'count_then'
  ) then
    raise exception 'migration 137 rollback refuses count_then semantic correlation rules';
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
    'time_condition','entity_classification'
  ));

delete from public.schema_migrations
where version = 137 and name = 'semantic_count_then_rule_kind';

commit;
