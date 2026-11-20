-- Explicit operator rollback only; never invoked by runtime.
begin;
select pg_advisory_xact_lock(hashtext('sli_identity_attack_rules_v301'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=301 and name='identity_attack_rules')
       or exists(select 1 from public.schema_migrations where version>301) then
        raise exception 'migration 301 rollback prerequisites failed';
    end if;
end $$;
set local lock_timeout='5s';
set local role adlog_storage_owner;

drop function public.default_detection_sources();
alter function public.default_detection_sources_before_v301() rename to default_detection_sources;
drop function public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text);
alter function public.resolve_finding_evidence_ref_before_v301(uuid,text,text,text,text,text,text,text)
    rename to resolve_finding_evidence_ref;

-- Restore definitions before dropping helpers they reference. Constraint validation
-- deliberately aborts rollback if directory evidence still requires the new kind.
do $$ declare r record; begin
    for r in select statement from public.identity_attack_rollback_v301 where phase<90 order by phase loop
        execute r.statement;
    end loop;
end $$;
drop function public.read_identity_snapshot_finding_evidence_v301(bigint,bigint[],bigint,integer);
drop function public.read_identity_attack_snapshot_v301(jsonb,bigint[]);
drop function public.read_identity_attack_events_v301(jsonb,bigint[]);
drop function public.identity_attack_episode_v301(jsonb,text,text,timestamptz,text);
drop function public.identity_attack_episode_known_v301(jsonb,text,text,text);
drop function public.identity_snapshot_rows_v301(jsonb,bigint[]);
drop table public.semantic_identity_attack_episodes_v301;
drop index public.idx_identity_attack_source_time_v301;

reset role;
alter table public.findings drop column identity_presentation_json;
do $$ declare r record; begin
    for r in select statement from public.identity_attack_rollback_v301 where phase=90 loop
        execute r.statement;
    end loop;
end $$;
set local role adlog_storage_owner;
drop table public.identity_attack_rollback_v301;
delete from public.schema_migrations where version=301 and name='identity_attack_rules';
commit;
