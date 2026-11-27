begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_sigma_live447_migration'));
select pg_advisory_xact_lock(hashtext('sli_sigma_live433_worker'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
        or not exists(select 1 from public.schema_migrations where version=447 and name='sigma_live')
        or exists(select 1 from public.schema_migrations where version>447) then
        raise exception 'sigma_live447_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

alter policy detection_match_scope on public.semantic_detection_matches
with check (public.resolve_finding_evidence_ref_before_v301(
    (document_json#>>'{evidence,scope,installation_id}')::uuid,
    document_json#>>'{evidence,scope,plugin_id}',document_json#>>'{evidence,scope,source_instance_id}',
    document_json#>>'{evidence,scope,source_generation}',document_json#>>'{evidence,scope,collection_scope_id}',
    document_json#>>'{evidence,storage_kind}',document_json#>>'{evidence,native_id}',
    document_json#>>'{evidence,sha256}'));

drop trigger sigma_enqueue433 on public.event_hot;
drop function public.sigma_enqueue433();
drop function public.apply_sigma_repeats433(text,integer);
drop function public.read_admitted_sigma_events(integer);
drop function public.ensure_sigma_starter_policy433(text,text);
drop function public.sigma_live_toggle433(uuid,boolean,text);
drop function public.sigma_live_list433();
drop function public.sigma_starter433();

-- Keep published findings and their provenance. Stop admission and audit it.
update public.semantic_policy_admission set enabled=false,updated_by='system:sigma-rollback',updated_at=now()
where policy_id like 'default:sigma:%' and enabled;
drop table public.sigma_live_subjects433,public.sigma_live_hits433,public.sigma_live_rules433,
    public.sigma_live_position433,public.sigma_live_inbox433;
delete from public.schema_migrations where version=447 and name='sigma_live';
set local role adlog_plugin_lifecycle_owner;
revoke select(plugin_id,package_lifecycle,desired_activation,component_runtime)
    on public.plugin_installations_v1 from adlog_storage_owner;
reset role;
commit;
