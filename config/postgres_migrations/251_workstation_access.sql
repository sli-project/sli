-- WR03: explicit WS authority; existing report assignments remain unchanged.
begin;
select pg_advisory_xact_lock(hashtext('sli_workstation_access_v251'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=249 and name='watch_registry')
       or not exists(select 1 from public.report_datasets_v4 where dataset_key='workstations.security' and version=1)
       or exists(select 1 from public.schema_migrations where version>=251) then
        raise exception 'migration 251 prerequisites failed';
    end if;
end $$;

-- Registration is not assignment: no role/package/user gains decision rights.
insert into public.access_capabilities(capability_key,label,description) values
    ('workstations.read','Read workstations','Read workstation data within an atomic report grant'),
    ('workstations.review','Review workstation findings','Acknowledge a specific finding revision in the readable scope'),
    ('workstations.exception.station','Allow a station exception','Create temporary exceptions for a readable station'),
    ('workstations.exception.account','Allow an account exception','Create temporary account exceptions within the complete readable scope'),
    ('workstations.exception.ou','Allow a department exception','Create temporary exceptions for a domain-bound organizational unit'),
    ('workstations.decision.manage','Manage workstation decisions','Read decision audit and revoke decisions within the readable scope');

-- Separate read grant for the new workspace. Four legacy grants retain their
-- family-specific scope and never imply review/exception/management authority.
insert into public.report_registry_v4(report_key,version,name,owner_name,purpose,dataset_id,
    definition_json,sensitivity,status,published_at)
select 'workstations.overview',1,'Workstations','sli.workstations','Scoped workstation workspace',id,
    '{"field_categories":["identity_basic","technical","security","privilege"],"actions":["view"]}'::jsonb,
    'restricted','published',now()
from public.report_datasets_v4 where dataset_key='workstations.security' and version=1;

insert into public.schema_migrations(version,name) values(251,'workstation_access');
commit;
