begin;

select pg_advisory_xact_lock(hashtext('ad_log_investigation_typed_evidence_refs_v136_rollback'));

drop table if exists public.investigation_evidence_refs;

delete from public.schema_migrations
where version = 136 and name = 'investigation_typed_evidence_refs';

commit;
