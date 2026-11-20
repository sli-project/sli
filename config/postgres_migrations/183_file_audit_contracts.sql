-- Stage 1: prepared file-audit namespace and draft report contracts only.
begin;
select pg_advisory_xact_lock(hashtext('sli_file_audit_contracts_v183'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 183 requires storage owner membership';
    end if;
    if not exists(select 1 from public.schema_migrations where version=182 and name='bundled_ad_gpo_defaults')
       or exists(select 1 from public.schema_migrations where version>=183) then
        raise exception 'migration 183 requires exact migration 182 bundled_ad_gpo_defaults and unused version 183';
    end if;
    if to_regnamespace('sli_plugin_file_audit') is not null
       or to_regrole('adlog_file_audit_owner') is not null
       or to_regrole('adlog_file_audit_runtime') is not null then
        raise exception 'migration 183 requires absent file audit namespace and roles';
    end if;
end $$;

create role adlog_file_audit_owner nologin noinherit nosuperuser nocreatedb nocreaterole nobypassrls noreplication;
create role adlog_file_audit_runtime nologin noinherit nosuperuser nocreatedb nocreaterole nobypassrls noreplication;
grant adlog_file_audit_owner,adlog_file_audit_runtime to adlog_storage_owner;
create schema sli_plugin_file_audit authorization adlog_file_audit_owner;
revoke all on schema sli_plugin_file_audit from public,adlog_user;
grant usage on schema sli_plugin_file_audit to adlog_file_audit_runtime;
set local role adlog_file_audit_owner;

create table sli_plugin_file_audit.settings (
    agent_id uuid not null,
    source_instance_id text not null check(length(source_instance_id) between 1 and 256),
    enabled boolean not null default false,
    source_payload_days integer not null default 7 check(source_payload_days=7),
    acl_history_days integer not null default 365 check(acl_history_days=365),
    facts_retention text not null default 'permanent' check(facts_retention='permanent'),
    file_event_cleanup_enabled boolean not null default false check(not file_event_cleanup_enabled),
    mass_operation_files integer not null default 100 check(mass_operation_files between 1 and 1000000),
    mass_operation_seconds integer not null default 300 check(mass_operation_seconds between 1 and 86400),
    working_time_source text not null default 'sli.settings' check(working_time_source='sli.settings'),
    primary key(agent_id,source_instance_id)
);
create table sli_plugin_file_audit.policy_revisions (
    agent_id uuid not null,
    source_instance_id text not null,
    revision bigint not null check(revision between 1 and 9007199254740991),
    authored_at timestamptz not null,
    actor_kind text not null check(actor_kind in ('session','api_key')),
    actor_id bigint not null check(actor_id>0),
    policy jsonb not null check(jsonb_typeof(policy)='object' and octet_length(policy::text)<=262144),
    policy_sha256 text not null check(policy_sha256 ~ '^[a-f0-9]{64}$'),
    primary key(agent_id,source_instance_id,revision)
);
-- References imported core evidence; the plugin does not store a second XML
-- archive and does not cascade away historical references when hot text expires.
create table sli_plugin_file_audit.observations (
    evidence_key text primary key check(evidence_key ~ '^[a-f0-9]{64}$'),
    agent_id uuid not null,
    source_instance_id text not null check(length(source_instance_id) between 1 and 256),
    collection_scope_id text not null check(length(collection_scope_id) between 1 and 256),
    channel text not null check(channel='Security'),
    provider text not null check(provider='Microsoft-Windows-Security-Auditing'),
    generation text not null check(length(generation) between 1 and 256),
    record_id bigint not null check(record_id>0),
    event_id integer not null check(event_id in (4656,4658,4659,4660,4663,4664,4670,4907,5140,5142,5143,5144,5145,5168)),
    event_version integer not null check(event_version between 0 and 255),
    observed_at timestamptz not null,
    policy_revision bigint not null check(policy_revision between 1 and 9007199254740991),
    core_evidence_ref text not null check(length(core_evidence_ref) between 1 and 512),
    payload_sha256 text not null check(payload_sha256 ~ '^[a-f0-9]{64}$'),
    unique(agent_id,source_instance_id,channel,generation,record_id)
);
create index file_audit_observation_window on sli_plugin_file_audit.observations(source_instance_id,observed_at,evidence_key);
create table sli_plugin_file_audit.actions (
    action_id text primary key check(action_id ~ '^[a-f0-9]{64}$'),
    contract_version integer not null check(contract_version=1),
    agent_id uuid not null,
    source_instance_id text not null,
    collection_scope_id text not null,
    observed_at timestamptz not null,
    subject_sid text,
    subject_entity_id bigint check(subject_entity_id>0),
    logon_id text,
    path text check(length(path)<=4096),
    share_name text,
    object_type text check(object_type in ('file','directory','unknown')),
    access_mask bigint check(access_mask between 0 and 4294967295),
    operation text not null check(operation in ('access_check','read','write','delete_right','delete','permissions','share_change','audit_change','unknown')),
    outcome text not null default 'unknown' check(outcome in ('success','failure','unknown')),
    client_ip inet,
    client_ip_source text,
    server_process_id bigint check(server_process_id>=0),
    handle_id text,
    correlation_state text not null default 'not_attempted' check(correlation_state in ('not_attempted','complete','partial','ambiguous')),
    projection_version integer not null check(projection_version>0),
    check((client_ip is null)=(client_ip_source is null))
);
create index file_audit_action_window on sli_plugin_file_audit.actions(source_instance_id,collection_scope_id,observed_at,action_id);
create index file_audit_action_subject on sli_plugin_file_audit.actions(subject_sid,observed_at,action_id);
create index file_audit_action_path on sli_plugin_file_audit.actions(source_instance_id,md5(path),observed_at,action_id);
create table sli_plugin_file_audit.action_evidence (
    action_id text not null references sli_plugin_file_audit.actions(action_id),
    core_evidence_ref text not null check(length(core_evidence_ref) between 1 and 512),
    -- Shared logon/control evidence stays with its existing normalizer owner.
    evidence_key text references sli_plugin_file_audit.observations(evidence_key),
    role text not null check(role in ('primary','handle_context','logon_context','control')),
    primary key(action_id,core_evidence_ref)
);
create table sli_plugin_file_audit.access_snapshots (
    snapshot_id uuid primary key,
    agent_id uuid not null,
    source_instance_id text not null,
    collection_scope_id text not null,
    observed_at timestamptz not null,
    contract_version integer not null check(contract_version=1),
    completeness text not null check(completeness in ('complete','partial','failed')),
    snapshot_sha256 text not null check(snapshot_sha256 ~ '^[a-f0-9]{64}$'),
    snapshot jsonb not null check(jsonb_typeof(snapshot)='object' and octet_length(snapshot::text)<=8388608),
    unread_objects integer not null check(unread_objects>=0),
    check(completeness<>'complete' or unread_objects=0)
);
create index file_audit_snapshot_window on sli_plugin_file_audit.access_snapshots(source_instance_id,collection_scope_id,observed_at,snapshot_id);
create table sli_plugin_file_audit.coverage (
    coverage_id uuid primary key,
    agent_id uuid not null,
    source_instance_id text not null,
    collection_scope_id text not null,
    policy_revision bigint not null check(policy_revision between 1 and 9007199254740991),
    window_start timestamptz not null,
    window_end timestamptz not null check(window_end>=window_start),
    state text not null check(state in ('complete','partial','gap','unknown')),
    read_audit_enabled boolean not null,
    filtered_count bigint not null check(filtered_count>=0),
    lost_count bigint check(lost_count>=0),
    reason_code text,
    details jsonb not null check(jsonb_typeof(details)='object' and octet_length(details::text)<=16384)
);
create index file_audit_coverage_window on sli_plugin_file_audit.coverage(source_instance_id,collection_scope_id,window_start,window_end);
create table sli_plugin_file_audit.audit_commands (
    command_id text primary key check(length(command_id) between 1 and 128),
    agent_id uuid not null,
    source_instance_id text not null,
    policy_revision bigint not null check(policy_revision between 1 and 9007199254740991),
    action text not null check(action in ('check','apply','restore')),
    collection_scope_ids text[] not null check(cardinality(collection_scope_ids) between 1 and 100),
    requested_at timestamptz not null,
    actor_kind text not null check(actor_kind in ('session','api_key')),
    actor_id bigint not null check(actor_id>0),
    command_sha256 text not null check(command_sha256 ~ '^[a-f0-9]{64}$'),
    unique(command_id,agent_id,source_instance_id,policy_revision,action)
);
-- Append-only receipts retain partial attempts and later verified readback.
create table sli_plugin_file_audit.audit_receipts (
    receipt_id uuid primary key,
    command_id text not null,
    agent_id uuid not null,
    source_instance_id text not null,
    policy_revision bigint not null check(policy_revision between 1 and 9007199254740991),
    action text not null check(action in ('check','apply','restore')),
    collection_scope_id text not null check(length(collection_scope_id) between 1 and 256),
    state text not null check(state in ('pending','verified','partial','blocked','failed')),
    observed_at timestamptz,
    result_sha256 text check(result_sha256 ~ '^[a-f0-9]{64}$'),
    reason_code text,
    check(state<>'verified' or (observed_at is not null and result_sha256 is not null)),
    foreign key(command_id,agent_id,source_instance_id,policy_revision,action)
        references sli_plugin_file_audit.audit_commands(command_id,agent_id,source_instance_id,policy_revision,action)
);
create index file_audit_receipt_command on sli_plugin_file_audit.audit_receipts(command_id,collection_scope_id,observed_at,receipt_id);

-- No automatic role membership for the application, and no UPDATE/DELETE on
-- immutable evidence, revisions, snapshots or receipts. A future core executor
-- must admit the reviewed rights profile before using this prepared role.
revoke all on all tables in schema sli_plugin_file_audit from public,adlog_user;
grant select,insert on sli_plugin_file_audit.settings,sli_plugin_file_audit.policy_revisions,
    sli_plugin_file_audit.observations,sli_plugin_file_audit.actions,
    sli_plugin_file_audit.action_evidence,sli_plugin_file_audit.access_snapshots,
    sli_plugin_file_audit.coverage,sli_plugin_file_audit.audit_commands,
    sli_plugin_file_audit.audit_receipts to adlog_file_audit_runtime;
reset role;

-- Draft data passports have no frontend definitions, navigation or assignments.
insert into public.access_capabilities(capability_key,label,description) values
    ('file-audit.view','File audit view','View evidence in the assigned file-server scope'),
    ('file-audit.export','File audit export','Export evidence in the assigned file-server scope'),
    ('file-audit.audit.manage','File audit management','Administrator AG-AUDIT commands in the assigned scope');
with definitions(key) as (values
    ('overview'),('actions'),('mass-operations'),('permission-changes'),
    ('access-denials'),('out-of-hours'),('permissions'),('audit-state')
)
insert into public.report_datasets_v4(dataset_key,version,name,object_type,fields_json,filters_json,actions_json,status)
select 'file-audit.'||key,1,'file-audit.'||key,'file',
    '[{"key":"subject_sid","category":"identity_basic"},{"key":"source_instance_id","category":"technical"},{"key":"path","category":"security"},{"key":"acl","category":"privilege"}]'::jsonb,
    '["period","source_instance_id","collection_scope_id"]'::jsonb,'["view","export"]'::jsonb,'draft'
from definitions;
insert into public.report_registry_v4(report_key,version,name,owner_name,purpose,dataset_id,definition_json,sensitivity,status)
select dataset_key,1,dataset_key,'sli.file-audit','File-server evidence contract',id,
    '{"field_categories":["identity_basic","technical","security","privilege"],"actions":["view","export"]}'::jsonb,
    'restricted','draft'
from public.report_datasets_v4 where dataset_key like 'file-audit.%' and version=1;
insert into public.schema_migrations(version,name) values(183,'file_audit_contracts');
commit;
