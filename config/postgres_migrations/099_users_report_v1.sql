begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_users_report_v1'));

insert into access_capabilities(capability_key,label,description) values
('account_risks.accept','Подтверждать допустимость риска учётной записи','Сроковое аудируемое решение для точной пары учётная запись + риск + версия правила')
on conflict(capability_key) do update set label=excluded.label,description=excluded.description;

insert into access_package_capabilities(package_id,capability_id)
select package.id,capability.id
from access_packages package
join access_capabilities capability on capability.capability_key='account_risks.accept'
where package.package_key='ad_auditor'
on conflict do nothing;

insert into report_datasets_v4(
    dataset_key,version,name,object_type,fields_json,filters_json,actions_json,status
) values (
    'ad.accounts.users',1,'Пользователи Active Directory','ad_user',
    '[
      {"key":"entity_id","label":"ID объекта","category":"identity_basic"},
      {"key":"display_name","label":"Пользователь","category":"identity_basic"},
      {"key":"natural_key","label":"Учётная запись","category":"technical"},
      {"key":"enabled","label":"Включена","category":"security"},
      {"key":"ou_path","label":"OU","category":"identity_basic"},
      {"key":"department","label":"Подразделение","category":"hr"},
      {"key":"title","label":"Должность","category":"hr"},
      {"key":"email","label":"Рабочая почта","category":"contact"},
      {"key":"last_logon_utc","label":"Последний наблюдаемый вход","category":"security"},
      {"key":"password_last_set_utc","label":"Смена пароля","category":"security"},
      {"key":"direct_privileges","label":"Прямые привилегии","category":"privilege"},
      {"key":"risks","label":"Квалифицированные риски","category":"security"},
      {"key":"observed_at_utc","label":"Наблюдалось","category":"security"}
    ]'::jsonb,
    '[
      {"key":"view","ops":["eq"]},
      {"key":"department","ops":["eq"]},
      {"key":"ou","ops":["eq"]},
      {"key":"risk_key","ops":["eq"]},
      {"key":"q","ops":["contains"]}
    ]'::jsonb,
    '["view","export","start_case","accept_risk"]'::jsonb,
    'published'
)
on conflict(dataset_key,version) do update set
    name=excluded.name,object_type=excluded.object_type,fields_json=excluded.fields_json,
    filters_json=excluded.filters_json,actions_json=excluded.actions_json,status=excluded.status;

insert into report_registry_v4(
    report_key,version,name,owner_name,purpose,dataset_id,definition_json,
    sensitivity,status,published_at
)
select
    'ad.users',1,'Пользователи','ИБ + администраторы доступов',
    'Единое рабочее пространство состояния, прямых привилегий и рисков учётных записей AD',
    dataset.id,
    jsonb_build_object(
        'target_path','/users-report',
        'required_capabilities',array['objects.view'],
        'field_categories',array['identity_basic','technical','security','privilege','hr','contact'],
        'actions',array['view','export','start_case','accept_risk'],
        'default_sort',jsonb_build_array(),
        'columns',dataset.fields_json,
        'filters',dataset.filters_json,
        'export_policy','controlled'
    ),
    'confidential','published',now()
from report_datasets_v4 dataset
where dataset.dataset_key='ad.accounts.users' and dataset.version=1
on conflict(report_key,version) do update set
    name=excluded.name,owner_name=excluded.owner_name,purpose=excluded.purpose,
    dataset_id=excluded.dataset_id,definition_json=excluded.definition_json,
    sensitivity=excluded.sensitivity,status='published',
    published_at=coalesce(report_registry_v4.published_at,now());

insert into access_package_reports(
    package_id,report_key,field_categories,allowed_actions,scope_json
)
select package.id,'ad.users',
       array['identity_basic','technical','security','privilege','hr','contact'],
       array['view','export','start_case','accept_risk'],
       '{"kind":"all"}'::jsonb
from access_packages package
where package.package_key='ad_auditor'
on conflict(package_id,report_key) do update set
    field_categories=excluded.field_categories,
    allowed_actions=excluded.allowed_actions,
    scope_json=excluded.scope_json;

create table if not exists account_risk_acceptances (
    id bigserial primary key,
    public_id uuid not null unique,
    entity_id bigint not null references entities_v2(id) on delete restrict,
    domain_id bigint not null references domains(id) on delete restrict,
    risk_key text not null,
    rule_version integer not null check(rule_version > 0),
    reason text not null check(length(trim(reason)) between 3 and 2000),
    responsible text not null check(length(trim(responsible)) between 1 and 256),
    status text not null default 'active' check(status in ('active','expired','revoked','superseded')),
    valid_from timestamptz not null default now(),
    valid_until timestamptz not null,
    created_by text not null,
    created_at timestamptz not null default now(),
    revoked_by text,
    revoked_at timestamptz,
    revoke_reason text,
    check(valid_until > valid_from),
    check((status='revoked') = (revoked_at is not null))
);

create unique index if not exists account_risk_acceptances_active_key
    on account_risk_acceptances(entity_id,risk_key,rule_version)
    where status='active';
create index if not exists account_risk_acceptances_domain_status
    on account_risk_acceptances(domain_id,status,valid_until);

create table if not exists account_risk_acceptance_audit (
    id bigserial primary key,
    acceptance_id bigint not null references account_risk_acceptances(id) on delete restrict,
    action text not null check(action in ('created','updated','revoked')),
    actor text not null,
    snapshot_json jsonb not null,
    created_at timestamptz not null default now()
);

create or replace function audit_account_risk_acceptance_change()
returns trigger language plpgsql as $$
begin
    insert into account_risk_acceptance_audit(acceptance_id,action,actor,snapshot_json)
    values(
        new.id,
        case when tg_op='INSERT' then 'created'
             when new.status='revoked' and old.status is distinct from 'revoked' then 'revoked'
             else 'updated' end,
        case when tg_op='INSERT' then new.created_by else coalesce(new.revoked_by,new.created_by) end,
        to_jsonb(new)
    );
    return new;
end;
$$;

drop trigger if exists account_risk_acceptance_audit_trigger on account_risk_acceptances;
create trigger account_risk_acceptance_audit_trigger
after insert or update on account_risk_acceptances
for each row execute function audit_account_risk_acceptance_change();

create table if not exists account_risk_investigation_links (
    id bigserial primary key,
    investigation_id bigint not null unique references investigations(id) on delete restrict,
    entity_id bigint not null references entities_v2(id) on delete restrict,
    domain_id bigint not null references domains(id) on delete restrict,
    risk_key text not null,
    rule_version integer not null check(rule_version > 0),
    qualification_snapshot jsonb not null,
    created_by text not null,
    created_at timestamptz not null default now()
);
create index if not exists account_risk_investigation_links_subject
    on account_risk_investigation_links(entity_id,risk_key,created_at desc);

do $$
begin
    if exists(select 1 from pg_roles where rolname='adlog_user') then
        execute 'grant select,insert,update on account_risk_acceptances to adlog_user';
        execute 'grant select on account_risk_acceptance_audit to adlog_user';
        execute 'grant select,insert on account_risk_investigation_links to adlog_user';
        execute 'grant usage,select on sequence account_risk_acceptances_id_seq,account_risk_acceptance_audit_id_seq,account_risk_investigation_links_id_seq to adlog_user';
    end if;
end $$;

insert into schema_migrations(version,name) values(99,'users_report_v1')
on conflict(version) do update set name=excluded.name;

commit;
