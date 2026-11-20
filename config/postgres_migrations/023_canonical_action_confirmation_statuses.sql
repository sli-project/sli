-- SEMANTIC-2: explicit evidence-confidence states for canonical actions.
-- This migration does not enable a worker, risk engine, finding creation,
-- collector, or production runtime route.

begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_canonical_action_statuses_v23'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 023 requires membership in adlog_storage_owner';
    end if;
    if to_regclass('canonical_actions') is null then
        raise exception 'migration 023 requires canonical_actions from migration 022';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=22 and name='semantic_processing_foundation'
    ) then
        raise exception 'migration 023 requires schema migration 022';
    end if;
end
$$;

set local role adlog_storage_owner;

-- ``confirmed`` was a provisional status in the first foundation.  Preserve
-- its evidence, but require a more explicit confirmation basis going forward.
update canonical_actions
set action_status = 'partially_confirmed'
where action_status = 'confirmed';

do $$
declare
    constraint_name text;
begin
    select conname into constraint_name
    from pg_constraint
    where conrelid = 'canonical_actions'::regclass
      and contype = 'c'
      and pg_get_constraintdef(oid) like '%action_status%';
    if constraint_name is not null then
        execute format('alter table canonical_actions drop constraint %I', constraint_name);
    end if;
end
$$;

alter table canonical_actions
    add constraint canonical_actions_action_status_check
    check (action_status in (
        'observed',
        'partially_confirmed',
        'state_confirmed',
        'multi_source_confirmed',
        'contradicted',
        'superseded',
        'quarantined'
    ));

insert into schema_migrations(version, name)
values (23, 'canonical_action_confirmation_statuses')
on conflict(version) do update set name=excluded.name;

commit;
