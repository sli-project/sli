-- Register product-bundled AD/GPO importers without changing source assignments.
begin;
select pg_advisory_xact_lock(hashtext('sli_bundled_ad_gpo_defaults_v182'));

do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 182 requires storage owner membership';
    end if;
    if not exists(select 1 from public.schema_migrations where version=181 and name='ad_state_privilege_category')
       or exists(select 1 from public.schema_migrations where version>=182) then
        raise exception 'migration 182 requires exact migration 181 and unused version 182';
    end if;
end $$;

-- Match import and owner-controlled lifecycle changes; defaults are applied once.
select pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_runtime_v76'));
set local role adlog_plugin_lifecycle_owner;
insert into public.plugin_installations_v1(
    plugin_id,manifest_id,manifest_sha256,package_version,package_lifecycle,
    desired_activation,observed_health,component_runtime,queue_state,revision,immutable_evidence_count)
values
    ('sli.ad','sli.ad.package.v3','ae3ce3896bcca905ce6b6e2e3ce90920a12f7c1c69eaca8276d0d54674f0fab9',
     '1.0.0','registered','enabled_manual','unknown','running','drained',1,1),
    ('sli.gpo','sli.gpo.package.v3','15ecc5b3b0c18cad968b8c4215f558dc21f1a3580544ba2cea8d332f8742d78d',
     '1.0.0','registered','enabled_manual','unknown','running','drained',1,1)
on conflict(plugin_id) do nothing;

-- Enable an existing default-disabled registration, preserving an explicit
-- owner stop/detach, updated package metadata and every active admission lease.
update public.plugin_installations_v1 i
set desired_activation='enabled_manual',component_runtime='running',
    observed_health='unknown',revision=i.revision+1,updated_at_utc=now()
where i.plugin_id in ('sli.ad','sli.gpo') and i.package_lifecycle='registered'
    and i.desired_activation='disabled' and i.component_runtime='stopped'
    and i.queue_state='drained'
    and not exists(select 1 from public.plugin_lifecycle_operations_v1 o where o.plugin_id=i.plugin_id
        and o.requested_action in ('drain','disable','detach') and o.outcome='succeeded')
    and not exists(select 1 from public.plugin_component_admission_v1 a where a.plugin_id=i.plugin_id)
    and not exists(select 1 from public.plugin_component_leases_v1 l where l.plugin_id=i.plugin_id
        and l.released_at_utc is null and l.expires_at_utc>clock_timestamp());

-- Importer readiness is separate from the per-agent source binding and data.
insert into public.plugin_state_v1(plugin_id,configured)
values('sli.ad',true),('sli.gpo',true)
on conflict(plugin_id) do update set configured=true,updated_at_utc=now();
reset role;
insert into public.schema_migrations(version,name) values(182,'bundled_ad_gpo_defaults');
commit;
