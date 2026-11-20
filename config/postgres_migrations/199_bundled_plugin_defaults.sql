-- Register remaining product-bundled importers without changing source assignments.
begin;
select pg_advisory_xact_lock(hashtext('sli_bundled_plugin_defaults_v199'));

do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 199 requires storage owner membership';
    end if;
    if not exists(select 1 from public.schema_migrations where version=198 and name='file_audit_admin_actions')
       or exists(select 1 from public.schema_migrations where version>=199) then
        raise exception 'migration 199 requires exact migration 198 and unused version 199';
    end if;
end $$;

-- Match import and owner-controlled lifecycle changes; defaults are applied once.
select pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_runtime_v76'));
set local role adlog_plugin_lifecycle_owner;
insert into public.plugin_installations_v1(
    plugin_id,manifest_id,manifest_sha256,package_version,package_lifecycle,
    desired_activation,observed_health,component_runtime,queue_state,revision,immutable_evidence_count)
values
    ('sli.file-audit','sli.file-audit.package.v3','c888a38b684efee504907542f2ef8e74d48d5360ba01f67a3720495ba1d8ce20',
     '1.0.0','registered','enabled_manual','unknown','running','drained',1,1),
    ('sli.workstations','sli.workstations.package.v3','1af01f10b96b25973131c2a9a69e73c2307818fdd8b4477ef902757717511f28',
     '1.0.0','registered','enabled_manual','unknown','running','drained',1,1),
    ('sli.remote-access','sli.remote-access.package.v3','c5dae5b2aca19e0351e8a2f12e834586ef553234b60a5960a732a8604374a426',
     '1.0.0','registered','enabled_manual','unknown','running','drained',1,1)
on conflict(plugin_id) do nothing;

-- Enable an existing default-disabled registration, preserving an explicit
-- owner stop/detach, updated package metadata and every active admission lease.
update public.plugin_installations_v1 i
set desired_activation='enabled_manual',component_runtime='running',
    observed_health='unknown',revision=i.revision+1,updated_at_utc=now()
where i.plugin_id in ('sli.file-audit','sli.workstations','sli.remote-access') and i.package_lifecycle='registered'
    and i.desired_activation='disabled' and i.component_runtime='stopped'
    and i.queue_state='drained'
    and not exists(select 1 from public.plugin_lifecycle_operations_v1 o where o.plugin_id=i.plugin_id
        and o.requested_action in ('drain','disable','detach') and o.outcome='succeeded')
    and not exists(select 1 from public.plugin_component_admission_v1 a where a.plugin_id=i.plugin_id)
    and not exists(select 1 from public.plugin_component_leases_v1 l where l.plugin_id=i.plugin_id
        and l.released_at_utc is null and l.expires_at_utc>clock_timestamp());

-- Importer readiness is separate from the per-agent source binding and data.
insert into public.plugin_state_v1(plugin_id,configured)
values('sli.file-audit',true),('sli.workstations',true),('sli.remote-access',true)
on conflict(plugin_id) do update set configured=true,updated_at_utc=now();
reset role;
insert into public.schema_migrations(version,name) values(199,'bundled_plugin_defaults');
commit;
