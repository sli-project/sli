begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_investigation_evidence_v2'));

-- Event search can be routed to Storage V2 after V1 retention has removed the
-- same event.  Investigation evidence therefore stores the stable DB ID and
-- validates it in application code against either active store.
alter table investigation_events
    drop constraint if exists investigation_events_event_db_id_fkey;

comment on column investigation_events.event_db_id is
    'Stable evidence ID validated against events or events_v2_core at mutation time';

insert into schema_migrations(version, name)
values (16, 'investigation_evidence_v2')
on conflict(version) do update set name=excluded.name;

commit;
