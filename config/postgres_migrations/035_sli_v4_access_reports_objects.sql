begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_sli_v4_access_reports_objects'));

create table if not exists access_capabilities (
    id bigserial primary key,
    capability_key text not null unique,
    label text not null,
    description text not null default '',
    created_at timestamptz not null default now()
);

create table if not exists access_packages (
    id bigserial primary key,
    package_key text not null unique,
    name text not null,
    description text not null default '',
    is_system boolean not null default true,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create table if not exists access_package_capabilities (
    package_id bigint not null references access_packages(id) on delete cascade,
    capability_id bigint not null references access_capabilities(id) on delete cascade,
    primary key(package_id, capability_id)
);

create table if not exists access_role_packages (
    coarse_role text not null check(coarse_role in ('viewer','operator','admin')),
    package_id bigint not null references access_packages(id) on delete cascade,
    primary key(coarse_role, package_id)
);

create table if not exists access_groups (
    id bigserial primary key,
    group_key text not null unique,
    name text not null,
    description text not null default '',
    is_active boolean not null default true,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create table if not exists access_group_members (
    group_id bigint not null references access_groups(id) on delete cascade,
    user_id bigint not null references auth_users(id) on delete cascade,
    valid_from timestamptz,
    valid_until timestamptz,
    source text not null default 'direct',
    created_at timestamptz not null default now(),
    primary key(group_id, user_id)
);

create table if not exists access_subject_packages (
    id bigserial primary key,
    subject_type text not null check(subject_type in ('user','group')),
    subject_id bigint not null,
    package_id bigint not null references access_packages(id) on delete cascade,
    effect text not null default 'allow' check(effect in ('allow','deny')),
    valid_from timestamptz,
    valid_until timestamptz,
    business_reason text not null,
    approved_by text,
    source_type text not null default 'direct' check(source_type in ('group','direct','temporary','system')),
    created_by bigint,
    created_at timestamptz not null default now(),
    unique(subject_type, subject_id, package_id, effect, source_type)
);

create table if not exists access_capability_assignments (
    id bigserial primary key,
    subject_type text not null check(subject_type in ('user','group')),
    subject_id bigint not null,
    capability_id bigint not null references access_capabilities(id) on delete cascade,
    effect text not null check(effect in ('allow','deny')),
    scope_json jsonb not null default '{}'::jsonb,
    valid_from timestamptz,
    valid_until timestamptz,
    business_reason text not null,
    approved_by text,
    source_type text not null default 'direct' check(source_type in ('group','direct','temporary','system')),
    created_by bigint,
    created_at timestamptz not null default now()
);

create table if not exists report_datasets_v4 (
    id bigserial primary key,
    dataset_key text not null,
    version integer not null check(version > 0),
    name text not null,
    object_type text,
    fields_json jsonb not null,
    filters_json jsonb not null default '[]'::jsonb,
    actions_json jsonb not null default '[]'::jsonb,
    status text not null default 'published' check(status in ('draft','published','retired')),
    created_at timestamptz not null default now(),
    unique(dataset_key, version)
);

create table if not exists report_registry_v4 (
    id bigserial primary key,
    report_key text not null,
    version integer not null check(version > 0),
    name text not null,
    owner_name text not null,
    purpose text not null,
    dataset_id bigint not null references report_datasets_v4(id),
    definition_json jsonb not null,
    sensitivity text not null check(sensitivity in ('internal','restricted','confidential')),
    status text not null default 'draft' check(status in ('draft','published','retired')),
    published_at timestamptz,
    created_by bigint,
    created_at timestamptz not null default now(),
    unique(report_key, version)
);

create table if not exists access_package_reports (
    package_id bigint not null references access_packages(id) on delete cascade,
    report_key text not null,
    field_categories text[] not null default array[]::text[],
    allowed_actions text[] not null default array['view']::text[],
    scope_json jsonb not null default '{"kind":"all"}'::jsonb,
    primary key(package_id, report_key)
);

create table if not exists access_report_assignments (
    id bigserial primary key,
    subject_type text not null check(subject_type in ('user','group')),
    subject_id bigint not null,
    report_key text not null,
    access_level text not null default 'view' check(access_level in ('view','manage')),
    effect text not null default 'allow' check(effect in ('allow','deny')),
    scope_json jsonb not null default '{"kind":"all"}'::jsonb,
    field_categories text[] not null default array[]::text[],
    allowed_actions text[] not null default array['view']::text[],
    valid_from timestamptz,
    valid_until timestamptz,
    source_type text not null default 'direct' check(source_type in ('group','direct','temporary','system')),
    business_reason text not null,
    approved_by text,
    created_by bigint,
    created_at timestamptz not null default now()
);

create index if not exists access_report_assignments_subject_idx
    on access_report_assignments(subject_type, subject_id, report_key, effect, valid_until);
create index if not exists access_capability_assignments_subject_idx
    on access_capability_assignments(subject_type, subject_id, effect, valid_until);

create table if not exists user_report_preferences (
    user_id bigint not null references auth_users(id) on delete cascade,
    report_key text not null,
    pinned boolean not null default false,
    view_json jsonb not null default '{}'::jsonb,
    updated_at timestamptz not null default now(),
    primary key(user_id, report_key)
);

create table if not exists object_identity_links (
    id bigserial primary key,
    source_object_type text not null,
    source_object_id text not null,
    target_object_type text not null,
    target_object_id text not null,
    relation_type text not null default 'identity_link',
    source_name text not null,
    match_method text not null,
    confidence numeric(5,4) not null check(confidence between 0 and 1),
    observed_at timestamptz not null,
    valid_from timestamptz,
    valid_until timestamptz,
    created_at timestamptz not null default now(),
    unique(source_object_type, source_object_id, target_object_type, target_object_id, relation_type, source_name)
);

create table if not exists access_audit_v4 (
    id bigserial primary key,
    actor_type text not null,
    actor_id bigint,
    action text not null,
    subject_type text,
    subject_id bigint,
    target_type text,
    target_key text,
    reason text,
    outcome text not null default 'ok',
    details_json jsonb not null default '{}'::jsonb,
    remote_address text,
    created_at timestamptz not null default now()
);

insert into access_capabilities(capability_key,label,description) values
('workspace.view','Рабочее пространство','Персональная сборка разрешённых модулей'),
('reports.catalog','Каталог отчётов','Просмотр каталога и объяснений доступа'),
('reports.design','Конструктор отчётов','Создание безопасных представлений datasets'),
('reports.publish','Публикация отчётов','Версионирование и публикация отчётов'),
('reports.assign','Назначение отчётов','Управление report grants'),
('reports.export','Контролируемый экспорт','Экспорт только зарегистрированного представления и разрешённых полей'),
('objects.view','Объекты','Поиск и просмотр разрешённых объектов'),
('objects.groups','Членство в группах','Direct/nested group paths'),
('objects.privileges','Доступ и привилегии','Effective privilege paths'),
('events.view','События','Bounded event explorer'),
('evidence.exact','Точные доказательства','Exact event_db_id и raw evidence'),
('investigations.view','Расследования','Просмотр расследований'),
('investigations.manage','Управление расследованиями','Создание и изменение cases'),
('tasks.create','Создание задачи','Безопасная контролируемая задача'),
('semantic.review','Semantic SHADOW review','Просмотр TEST/SHADOW и калибровка'),
('operations.view','Эксплуатация','Workers, queues, PostgreSQL и SLO'),
('access.manage','Управление доступом','Пакеты, grants, scopes и сроки'),
('access.preview','Предпросмотр доступа','Explain и preview effective access'),
('access.impersonate','Просмотр от имени','Административный preview без обхода PDP'),
('field.identity_basic','Базовая идентификация','Имена, типы и стабильные ID'),
('field.contact','Рабочие контакты','Почта, телефон и расположение'),
('field.hr','Кадровые данные','Должность, отдел и руководитель'),
('field.security','Данные безопасности','Состояния и security facts'),
('field.privilege','Привилегии и отношения','Членства и effective privilege'),
('field.technical','Технические атрибуты','SID, GUID, DN, UAC, SPN'),
('field.raw_evidence','Raw evidence','EventData, message и точные поля'),
('field.sensitive','Чувствительные поля','Ограниченные персональные данные')
on conflict(capability_key) do update set label=excluded.label,description=excluded.description;

insert into access_packages(package_key,name,description) values
('security_operator','ИБ · операторы','Очередь проблем, влияние, гипотезы и безопасные действия'),
('security_analyst','ИБ · аналитики','События, evidence, entities и investigations'),
('ad_auditor','AD · аудит и сопровождение','AD-отчёты, группы, привилегии и GPO'),
('project_operations','Проект · эксплуатация','Источники, workers, queues, PostgreSQL и readiness'),
('access_admin','Администраторы доступа','Назначения, explain, preview и audit без автоматического чтения данных')
on conflict(package_key) do update set name=excluded.name,description=excluded.description,updated_at=now();

with mapping(package_key,capability_key) as (values
('security_operator','workspace.view'),('security_operator','reports.catalog'),('security_operator','objects.view'),
('security_operator','investigations.view'),('security_operator','investigations.manage'),('security_operator','tasks.create'),
('security_operator','field.identity_basic'),('security_operator','field.security'),
('security_analyst','workspace.view'),('security_analyst','reports.catalog'),('security_analyst','objects.view'),
('security_analyst','objects.groups'),('security_analyst','events.view'),('security_analyst','evidence.exact'),
('security_analyst','reports.export'),
('security_analyst','investigations.view'),('security_analyst','investigations.manage'),('security_analyst','tasks.create'),
('security_analyst','semantic.review'),('security_analyst','field.identity_basic'),('security_analyst','field.security'),
('security_analyst','field.privilege'),('security_analyst','field.technical'),('security_analyst','field.raw_evidence'),
('ad_auditor','workspace.view'),('ad_auditor','reports.catalog'),('ad_auditor','objects.view'),
('ad_auditor','objects.groups'),('ad_auditor','objects.privileges'),('ad_auditor','tasks.create'),
('ad_auditor','reports.export'),
('ad_auditor','field.identity_basic'),('ad_auditor','field.contact'),('ad_auditor','field.hr'),
('ad_auditor','field.security'),('ad_auditor','field.privilege'),('ad_auditor','field.technical'),
('project_operations','workspace.view'),('project_operations','reports.catalog'),('project_operations','operations.view'),
('project_operations','reports.export'),
('access_admin','workspace.view'),('access_admin','reports.catalog'),('access_admin','reports.design'),
('access_admin','reports.publish'),('access_admin','reports.assign'),('access_admin','reports.export'),('access_admin','access.manage'),
('access_admin','access.preview'),('access_admin','access.impersonate')
)
insert into access_package_capabilities(package_id,capability_id)
select p.id,c.id from mapping m join access_packages p on p.package_key=m.package_key
join access_capabilities c on c.capability_key=m.capability_key
on conflict do nothing;

with mapping(coarse_role,package_key) as (values
('viewer','security_analyst'),
('operator','security_analyst'),('operator','ad_auditor'),('operator','project_operations'),
('admin','project_operations'),('admin','access_admin')
)
insert into access_role_packages(coarse_role,package_id)
select m.coarse_role,p.id from mapping m join access_packages p on p.package_key=m.package_key
on conflict do nothing;

insert into report_datasets_v4(dataset_key,version,name,object_type,fields_json,filters_json,actions_json) values
('security.problems',1,'Очередь проблем ИБ','finding','[{"key":"title","label":"Проблема","category":"security"},{"key":"severity","label":"Risk","category":"security"},{"key":"status","label":"Статус","category":"security"},{"key":"evidence_event_id","label":"Evidence DB ID","category":"raw_evidence"}]','[{"key":"severity","ops":["eq","in"]},{"key":"status","ops":["eq","in"]}]','["view","create_task","start_case"]'),
('events.v2',1,'События Storage V2','event','[{"key":"id","label":"Event DB ID","category":"raw_evidence"},{"key":"time_created_utc","label":"UTC","category":"security"},{"key":"event_id","label":"Event ID","category":"security"},{"key":"channel","label":"Канал","category":"technical"},{"key":"subject_user_name","label":"Инициатор","category":"security"},{"key":"target_user_name","label":"Объект","category":"security"}]','[{"key":"event_id","ops":["eq","in"]},{"key":"channel","ops":["eq"]},{"key":"time_created_utc","ops":["gte","lte"]}]','["view","export","start_case"]'),
('entities.v2',1,'Объекты и сущности','entity','[{"key":"id","label":"ID","category":"identity_basic"},{"key":"entity_type","label":"Тип","category":"identity_basic"},{"key":"display_name","label":"Имя","category":"identity_basic"},{"key":"natural_key","label":"Natural key","category":"technical"},{"key":"last_seen_utc","label":"Последнее наблюдение","category":"security"}]','[{"key":"entity_type","ops":["eq","in"]},{"key":"display_name","ops":["contains"]}]','["view","create_task","start_case"]'),
('ad.audit.snapshot',1,'Состояние и риски Active Directory','entity','[{"key":"display_name","label":"Объект","category":"identity_basic"},{"key":"entity_type","label":"Тип","category":"identity_basic"},{"key":"last_seen_utc","label":"Наблюдалось","category":"security"},{"key":"context_source","label":"Источник","category":"technical"}]','[{"key":"entity_type","ops":["eq","in"]}]','["view","create_task"]'),
('ad.accounts.privileged',1,'Привилегированные учётные записи','entity','[{"key":"display_name","label":"Учётная запись","category":"identity_basic"},{"key":"natural_key","label":"Login","category":"technical"},{"key":"privilege_path","label":"Путь получения","category":"privilege"},{"key":"last_seen_utc","label":"Наблюдалось","category":"security"}]','[{"key":"privilege","ops":["eq","in"]}]','["view","create_task","export"]'),
('ad.gpo.governance',1,'GPO — очередь ручной проверки','gpo','[{"key":"display_name","label":"GPO","category":"identity_basic"},{"key":"priority","label":"Приоритет","category":"security"},{"key":"owner","label":"Владелец","category":"identity_basic"},{"key":"observed_at","label":"Наблюдалось","category":"security"}]','[{"key":"priority","ops":["eq","in"]}]','["view","create_task"]'),
('operations.runtime',1,'Готовность и устойчивость проекта','runtime','[{"key":"component","label":"Компонент","category":"technical"},{"key":"state","label":"Состояние","category":"technical"},{"key":"checked_at","label":"Проверено","category":"technical"}]','[{"key":"state","ops":["eq","in"]}]','["view","export"]'),
('access.subjects',1,'Доступы пользователей и групп','access_subject','[{"key":"subject","label":"Пользователь или группа","category":"identity_basic"},{"key":"packages","label":"Пакеты","category":"technical"},{"key":"reports","label":"Отчёты","category":"technical"},{"key":"expires","label":"Срок","category":"technical"}]','[]','["view","grant_access"]')
on conflict(dataset_key,version) do update set name=excluded.name,fields_json=excluded.fields_json,filters_json=excluded.filters_json,actions_json=excluded.actions_json;

with definitions(report_key,name,owner_name,purpose,dataset_key,sensitivity,target_path,required_caps,field_categories,actions) as (values
('security.queue','Очередь проблем ИБ','ИБ','Что произошло, влияние, гипотеза и безопасный следующий шаг','security.problems','restricted','/scenarios',array['workspace.view'],array['security'],array['view','create_task','start_case']),
('events.explorer','Технические события','ИБ','Bounded evidence explorer с точным event_db_id','events.v2','confidential','/events',array['events.view'],array['security','technical','raw_evidence'],array['view','export','start_case']),
('investigations.workspace','Расследования','ИБ','Дела, evidence и решения аналитика','security.problems','restricted','/investigations',array['investigations.view'],array['security'],array['view','start_case']),
('ad.state','Состояние и риски Active Directory','AD / ИТ','Домен, DC, accounts, computers и контекст AD','ad.audit.snapshot','restricted','/objects',array['objects.view'],array['identity_basic','security','technical'],array['view','create_task']),
('ad.privileged','Привилегированные учётные записи','ИБ + ИТ','Direct/nested privileges и evidence path','ad.accounts.privileged','confidential','/objects?view=privileged',array['objects.privileges'],array['identity_basic','privilege','technical'],array['view','create_task','export']),
('ad.gpo.review','GPO — очередь ручной проверки','AD / ИТ','Приоритеты governance без прямого изменения GPO','ad.gpo.governance','restricted','/reports/ad.gpo.review',array['objects.view'],array['identity_basic','security'],array['view','create_task']),
('operations.readiness','Готовность и устойчивость проекта','Проект','Workers, queues, PostgreSQL и readiness','operations.runtime','internal','/operations',array['operations.view'],array['technical'],array['view','export']),
('access.center','Доступы пользователей и групп','Администратор доступа','Пакеты, grants, scopes, сроки и explain','access.subjects','confidential','/access',array['access.manage'],array[]::text[],array['view','grant_access'])
)
insert into report_registry_v4(report_key,version,name,owner_name,purpose,dataset_id,definition_json,sensitivity,status,published_at)
select d.report_key,1,d.name,d.owner_name,d.purpose,ds.id,
       jsonb_build_object('target_path',d.target_path,'required_capabilities',d.required_caps,'field_categories',d.field_categories,'actions',d.actions,'default_sort',jsonb_build_array(),'columns',ds.fields_json,'filters',ds.filters_json,'export_policy',case when 'export'=any(d.actions) then 'controlled' else 'disabled' end),
       d.sensitivity,'published',now()
from definitions d join report_datasets_v4 ds on ds.dataset_key=d.dataset_key and ds.version=1
on conflict(report_key,version) do update set name=excluded.name,purpose=excluded.purpose,definition_json=excluded.definition_json,status='published',published_at=coalesce(report_registry_v4.published_at,now());

with mapping(package_key,report_key,fields,actions) as (values
('security_operator','security.queue',array['identity_basic','security'],array['view','create_task','start_case']),
('security_analyst','security.queue',array['identity_basic','security','raw_evidence'],array['view','create_task','start_case']),
('security_analyst','events.explorer',array['identity_basic','security','technical','raw_evidence'],array['view','export','start_case']),
('security_analyst','investigations.workspace',array['identity_basic','security','raw_evidence'],array['view','start_case']),
('ad_auditor','ad.state',array['identity_basic','contact','hr','security','technical'],array['view','create_task']),
('ad_auditor','ad.privileged',array['identity_basic','security','privilege','technical'],array['view','create_task','export']),
('ad_auditor','ad.gpo.review',array['identity_basic','security','technical'],array['view','create_task']),
('project_operations','operations.readiness',array['technical'],array['view','export']),
('access_admin','access.center',array[]::text[],array['view','grant_access'])
)
insert into access_package_reports(package_id,report_key,field_categories,allowed_actions)
select p.id,m.report_key,m.fields,m.actions from mapping m join access_packages p on p.package_key=m.package_key
on conflict(package_id,report_key) do update set field_categories=excluded.field_categories,allowed_actions=excluded.allowed_actions;

insert into schema_migrations(version,name) values(35,'sli_v4_access_reports_objects')
on conflict(version) do update set name=excluded.name;

do $$
begin
    if exists(select 1 from pg_roles where rolname='adlog_user') then
        execute 'grant select on access_capabilities,access_packages,access_package_capabilities,access_role_packages,access_groups,access_group_members,access_subject_packages,access_capability_assignments,report_datasets_v4,report_registry_v4,access_package_reports,access_report_assignments,user_report_preferences,object_identity_links,access_audit_v4 to adlog_user';
        execute 'grant insert,update,delete on access_groups,access_group_members,access_subject_packages,access_capability_assignments,access_report_assignments,user_report_preferences,report_registry_v4,access_audit_v4 to adlog_user';
        execute 'grant usage,select on sequence access_groups_id_seq,access_subject_packages_id_seq,access_capability_assignments_id_seq,access_report_assignments_id_seq,report_registry_v4_id_seq,object_identity_links_id_seq,access_audit_v4_id_seq to adlog_user';
    end if;
end $$;

commit;
