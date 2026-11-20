-- Restore-safe history: contextual admission belongs at the live write boundary.
begin;
select pg_advisory_xact_lock(hashtext('sli_qw_restore_context_guards_v276'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=275 and name='password_policy_management')
       or exists(select 1 from public.schema_migrations where version>=276) then
        raise exception 'migration 276 prerequisites failed';
    end if;
end $$;
set local lock_timeout='5s';
set local role adlog_storage_owner;

-- Both predicates depend on live tables and the issuing session's identity.
-- A CHECK is re-evaluated during COPY, before all source/portion data exists,
-- and under the restoring login rather than the original publisher. Keep the
-- existing row-only CHECKs and RLS policies unchanged; do not revalidate sealed
-- history against today's assignments, frozen budgets or current session.
create function public.qw_context_guard_v276() returns trigger
language plpgsql security invoker set search_path=pg_catalog,pg_temp as $$
begin
    if (case when NEW.document_json->>'kind'='acl' or NEW.document_json ? 'acl_context'
      or starts_with(NEW.document_json->>'rule_id','qw.file-acl-')
      or jsonb_path_exists(NEW.document_json,'$.evidence_refs[*] ? (@.storage_kind == "file_audit_snapshot")')
      then public.file_acl_qw_row_allowed_v265(NEW.signal_id,NEW.evaluation_mode,NEW.document_json)
      else true end) is false then
        raise exception 'semantic QW ACL identity denied' using errcode='23514',
          constraint='semantic_qw_acl_identity_v265',table='semantic_qw_signals',schema='public';
    end if;
    if public.password_v2_qw_allowed(NEW.signal_id,NEW.evaluation_mode,NEW.document_json) is false then
        raise exception 'semantic QW password identity denied' using errcode='23514',
          constraint='password_v2_qw_identity',table='semantic_qw_signals',schema='public';
    end if;
    return NEW;
end $$;
revoke all on function public.qw_context_guard_v276()
  from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
-- BEFORE also rejects spoofed duplicate keys before ON CONFLICT DO NOTHING.
-- Invoker context preserves the existing helpers' session-user checks, without
-- adding any grants or changing owners, roles or helper function definitions.
create trigger aa_qw_context_guard_v276 before insert or update on public.semantic_qw_signals
  for each row execute function public.qw_context_guard_v276();
-- CHECKs also ran for replication-role writes. Preserve that property. pg_dump
-- creates this trigger in post-data, so a normal empty-database restore works
-- without disabling triggers, changing replication role or weakening runtime.
alter table public.semantic_qw_signals enable always trigger aa_qw_context_guard_v276;
alter table public.semantic_qw_signals
  drop constraint semantic_qw_acl_identity_v265,
  drop constraint password_v2_qw_identity;

insert into public.schema_migrations(version,name) values(276,'qw_restore_context_guards');
commit;
