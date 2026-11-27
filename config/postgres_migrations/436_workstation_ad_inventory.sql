begin;
select pg_advisory_xact_lock(hashtext('sli_workstation_ad_inventory436'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=435 and name='user_activity_indexes')
       or exists(select 1 from public.schema_migrations where version>=436) then
        raise exception 'workstation_ad_inventory436_preflight';
    end if;
end $$;
-- The package runner enters as the storage owner. The AD source
-- tables belong to the bootstrap roles, so grant as the session user.
reset role;
grant select(manifest_id,domain_id,slot_start_utc) on public.ad_snapshot_manifests to adlog_storage_owner;
grant select(manifest_id,family,contract_id,source_id,source_state,payload_sha256)
    on public.ad_snapshot_manifest_sources to adlog_storage_owner;
grant select(domain_id,snapshot_uuid,payload_json,payload_sha256,base_inventory_status,captured_at_utc)
    on public.computers_v6_source_snapshots to adlog_storage_owner;
set local role adlog_storage_owner;

alter table sli_plugin_workstations.station_inventory add column ad_snapshot_metadata jsonb;

create table sli_plugin_workstations.ad_inventory_checkpoints436 (
    domain_id bigint primary key references public.domains(id) on delete cascade,
    slot_start_utc timestamptz not null,
    manifest_id uuid not null
);
revoke all on sli_plugin_workstations.ad_inventory_checkpoints436 from public;
grant select on sli_plugin_workstations.ad_inventory_checkpoints436 to adlog_user;

-- The worker can only advance the published AD population. It supplies no
-- payload, identities, assignments or journal permissions.
create function public.advance_workstation_ad_inventory436() returns bigint
language plpgsql volatile security definer set search_path=pg_catalog,pg_temp as $$
declare
    source record;
    computer_rows jsonb;
begin
    if not public.workstation_runtime_enabled_v376()
       or not pg_try_advisory_xact_lock(hashtext('workstations.inventory-publication')) then
        return null;
    end if;

    select d.id as domain_id,m.slot_start_utc,m.manifest_id,snap.payload_json->'objects' as computers,
           snap.captured_at_utc
    into source
    from public.domains d
    cross join lateral (
        select m.manifest_id,m.slot_start_utc
        from public.ad_snapshot_manifests m
        where m.domain_id=d.id
        order by m.slot_start_utc desc,m.manifest_id desc limit 1
    ) m
    join public.ad_snapshot_manifest_sources member
      on member.manifest_id=m.manifest_id and member.family='computers_v6'
     and member.contract_id='sli.ad-computers.snapshot/2.0'
     and member.source_state in ('complete','partial')
    join public.computers_v6_source_snapshots snap
      on snap.domain_id=d.id and snap.snapshot_uuid=
         case when pg_input_is_valid(member.source_id,'uuid') then member.source_id::uuid end
     and snap.payload_sha256=member.payload_sha256 and snap.base_inventory_status='observed'
    left join sli_plugin_workstations.ad_inventory_checkpoints436 checkpoint on checkpoint.domain_id=d.id
    where checkpoint.domain_id is null
       or (checkpoint.slot_start_utc,checkpoint.manifest_id)<(m.slot_start_utc,m.manifest_id)
    order by m.slot_start_utc,d.id limit 1;
    if not found then return null; end if;

    select coalesce(jsonb_agg(jsonb_build_object(
        'id',alias.entity_id,
        'metadata',jsonb_build_object(
            'display_name',left(computer->>'name',256),
            'dns_host_name',left(computer->>'dnsHostName',256),
            'operating_system',left(computer->>'osName',256),
            'operating_system_version',left(computer->>'osVersion',256),
            'ou_path',left(computer->>'ou',2048),
            'last_logon_utc',case
                when computer->>'exactLastLogon' ~ '(Z|[+-][0-9]{2}:[0-9]{2})$'
                  and pg_input_is_valid(computer->>'exactLastLogon','timestamptz') then computer->>'exactLastLogon'
                when computer->>'lastLogonTimestamp' ~ '(Z|[+-][0-9]{2}:[0-9]{2})$'
                  and pg_input_is_valid(computer->>'lastLogonTimestamp','timestamptz') then computer->>'lastLogonTimestamp'
            end,
            'observed_at',source.captured_at_utc))), '[]'::jsonb)
    into computer_rows
    from jsonb_array_elements(source.computers) computer
    left join public.ad_context_entity_aliases alias
      on alias.domain_id=source.domain_id and alias.alias_type='object_guid'
     and alias.normalized_value=lower(computer->>'objectGuid')
    where lower(btrim(coalesce(computer->>'osName',''))) not in ('','unknown','неизвестно')
      and strpos(lower(computer->>'osName'),'server')=0
      and coalesce(computer#>>'{classification,result}',computer#>>'{classification,value}','') not in ('server','domain_controller')
      and coalesce(computer->>'deviceType','') not in ('server','domain_controller')
      and (case when pg_input_is_valid(computer->>'userAccountControl','bigint')
                then (computer->>'userAccountControl')::bigint & 8192 else 0 end)=0;

    -- Both publishers import the computer identities before publishing the
    -- manifest. A missing identity must leave the checkpoint retryable.
    if exists(select 1 from jsonb_array_elements(computer_rows) row where row->>'id' is null) then
        raise exception 'workstation_ad_inventory_identity_missing';
    end if;

    insert into sli_plugin_workstations.station_inventory as i
        (station_id,ad_computer_id,domain_id,station_type,metadata,metadata_observed_at,ad_snapshot_metadata)
    select 'ws:ad:'||(row->>'id'),(row->>'id')::bigint,source.domain_id,'workstation',
           row->'metadata',source.captured_at_utc,row->'metadata'
    from jsonb_array_elements(computer_rows) row
    on conflict(ad_computer_id) do update set
        ad_snapshot_metadata=excluded.ad_snapshot_metadata,
        revision=i.revision+1,updated_at=clock_timestamp()
    where i.domain_id=excluded.domain_id
      and (i.ad_snapshot_metadata-'observed_at') is distinct from (excluded.ad_snapshot_metadata-'observed_at');

    update sli_plugin_workstations.station_inventory i set
        ad_snapshot_metadata=null,revision=i.revision+1,updated_at=clock_timestamp()
    where i.domain_id=source.domain_id and i.ad_snapshot_metadata is not null
      and not exists(select 1 from jsonb_array_elements(computer_rows) row where (row->>'id')::bigint=i.ad_computer_id);

    insert into sli_plugin_workstations.ad_inventory_checkpoints436 as checkpoint(domain_id,slot_start_utc,manifest_id)
    values(source.domain_id,source.slot_start_utc,source.manifest_id)
    on conflict(domain_id) do update set slot_start_utc=excluded.slot_start_utc,manifest_id=excluded.manifest_id;
    return source.domain_id;
end $$;
revoke all on function public.advance_workstation_ad_inventory436() from public;
grant execute on function public.advance_workstation_ad_inventory436() to adlog_context_worker;

insert into public.schema_migrations(version,name) values(436,'workstation_ad_inventory');
commit;
