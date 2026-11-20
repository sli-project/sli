-- Allow the RADIUS session consumer to read only immutable manifest identity/hash metadata.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_radius_session_consumer_manifest_hash_v98')
);

set local role adlog_storage_owner;

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=61 and name='radius_session_consumer_projection'
    ) then
        raise exception 'migration 098 requires migration 061';
    end if;
    if exists(select 1 from schema_migrations where version=98) then
        raise exception 'migration 098 version is already recorded';
    end if;
    if to_regclass('public.core_evidence_manifests') is null then
        raise exception 'migration 098 requires core_evidence_manifests';
    end if;
    if not exists(
        select 1 from pg_roles where rolname='adlog_radius_session_consumer'
    ) then
        raise exception 'migration 098 requires adlog_radius_session_consumer';
    end if;
end
$$;

grant select (evidence_uid, canonical_record_sha256)
on core_evidence_manifests
to adlog_radius_session_consumer;

do $$
begin
    if not has_column_privilege(
        'adlog_radius_session_consumer',
        'core_evidence_manifests',
        'evidence_uid',
        'SELECT'
    ) or not has_column_privilege(
        'adlog_radius_session_consumer',
        'core_evidence_manifests',
        'canonical_record_sha256',
        'SELECT'
    ) then
        raise exception 'migration 098 manifest hash grant readback failed';
    end if;
end
$$;

insert into schema_migrations(version, name)
values (98, 'radius_session_consumer_manifest_hash');

commit;
