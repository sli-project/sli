begin;
select pg_advisory_xact_lock(hashtext('sli_workstation_ad_inventory436'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=436 and name='workstation_ad_inventory')
       or exists(select 1 from public.schema_migrations where version>436) then
        raise exception 'workstation_ad_inventory436_rollback_preflight';
    end if;
end $$;
set local role adlog_storage_owner;

drop function public.advance_workstation_ad_inventory436();
drop table sli_plugin_workstations.ad_inventory_checkpoints436;
alter table sli_plugin_workstations.station_inventory drop column ad_snapshot_metadata;
delete from public.schema_migrations where version=436 and name='workstation_ad_inventory';
reset role;
revoke select(manifest_id,domain_id,slot_start_utc) on public.ad_snapshot_manifests from adlog_storage_owner;
revoke select(manifest_id,family,contract_id,source_id,source_state,payload_sha256)
    on public.ad_snapshot_manifest_sources from adlog_storage_owner;
revoke select(domain_id,snapshot_uuid,payload_json,payload_sha256,base_inventory_status,captured_at_utc)
    on public.computers_v6_source_snapshots from adlog_storage_owner;
commit;
