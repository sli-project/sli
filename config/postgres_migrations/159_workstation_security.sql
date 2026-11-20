-- Workstation-owned projections. Generic identity and queue remain core-owned.
begin;
select pg_advisory_xact_lock(hashtext('sli_workstation_security_v159'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 159 requires membership in adlog_storage_owner';
    end if;
    if exists(select 1 from public.schema_migrations where version=159) then
        raise exception 'migration 159 already recorded';
    end if;
    if not exists(select 1 from public.schema_migrations where version=158 and name='ad_gpo_core_jobs')
       or exists(select 1 from public.schema_migrations where version>158) then
        raise exception 'migration 159 requires exact migration 158 ad_gpo_core_jobs';
    end if;
    if to_regclass('public.report_registry_v4') is null then
        raise exception 'migration 159 requires core report registry';
    end if;
end $$;

-- No membership is granted to the application login. The core executor must
-- explicitly admit this rights profile before running the retention handler.
create role adlog_workstations_retention nologin noinherit;
create schema sli_plugin_workstations authorization adlog_storage_owner;
set local role adlog_storage_owner;
revoke all on schema sli_plugin_workstations from public;
create table sli_plugin_workstations.observations (
    id text primary key check(id ~ '^[a-f0-9]{64}$'),
    agent_key text not null check(length(trim(agent_key)) between 1 and 256),
    entity_id bigint not null check(entity_id>0),
    ad_computer_id bigint check(ad_computer_id>0),
    family text not null check(family in ('logons','processes','usb','protection')),
    event_id integer not null check(event_id>0),
    observed_at timestamptz not null,
    observation jsonb not null check(jsonb_typeof(observation)='object'),
    observation_sha256 text not null check(observation_sha256 ~ '^[a-f0-9]{64}$'),
    source_xml text not null check(octet_length(source_xml) between 1 and 1048576)
);
create index workstation_report_window on sli_plugin_workstations.observations(agent_key,family,observed_at,id);
create index workstation_evidence_expiry on sli_plugin_workstations.observations(observed_at,id)
    where family in ('processes','usb');
revoke all on sli_plugin_workstations.observations from public,adlog_user;
grant usage on schema sli_plugin_workstations to adlog_user,adlog_workstations_retention;
grant insert on sli_plugin_workstations.observations to adlog_user;
grant select(id,agent_key,entity_id,ad_computer_id,family,event_id,observed_at,observation,observation_sha256)
    on sli_plugin_workstations.observations to adlog_user;
grant select,delete on sli_plugin_workstations.observations to adlog_workstations_retention;
reset role;
grant select(key,value) on public.platform_settings to adlog_workstations_retention;

-- Register reports without assigning any package, user or capability grant.
insert into public.report_datasets_v4(dataset_key,version,name,object_type,fields_json,filters_json,actions_json,status)
values ('workstations.security',1,'Workstation security','device',
    '[{"key":"agent_key","category":"identity_basic"},{"key":"event_id","category":"technical"},{"key":"facts","category":"security"},{"key":"administrators","category":"privilege"}]'::jsonb,
    '["period","agent_key"]'::jsonb,'["view"]'::jsonb,'published');
with definitions(report_key,name) as (values
    ('workstations.logons','Входы на станциях'),
    ('workstations.processes','Процессы и службы'),
    ('workstations.usb','Съёмные носители'),
    ('workstations.protection','Локальные администраторы и защита')
)
insert into public.report_registry_v4(report_key,version,name,owner_name,purpose,dataset_id,definition_json,sensitivity,status,published_at)
select d.report_key,1,d.name,'sli.workstations','Observed security evidence',dataset.id,
    '{"field_categories":["identity_basic","technical","security","privilege"],"actions":["view"]}'::jsonb,
    'restricted','published',now()
from definitions d join public.report_datasets_v4 dataset on dataset.dataset_key='workstations.security' and dataset.version=1;
insert into public.schema_migrations(version,name) values(159,'workstation_security');
commit;
