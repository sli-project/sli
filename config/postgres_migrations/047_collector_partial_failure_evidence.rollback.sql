begin;

alter table collector_channel_runs
    drop column if exists cursor_commit_allowed,
    drop column if exists failure_stage,
    drop column if exists partial_kind;

delete from schema_migrations
where version=47 and name='collector_partial_failure_evidence';

commit;
