-- Stage 8 process/activity semantic and durable storage foundation.
-- Source-only preparation: no worker, runtime, report, API or production apply.
begin;
set local lock_timeout='5s';
set local statement_timeout='30s';
set local search_path=pg_catalog,public;
select pg_advisory_xact_lock(hashtext('ad_log_reports_process_activity_foundation_v89'));

do $$
declare
    v_marker_count integer;
begin
    if to_regrole('adlog_storage_owner') is null
       or to_regrole('adlog_semantic_worker') is null then
        raise exception 'migration 089 requires storage owner and semantic worker roles';
    end if;
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 089 requires membership in adlog_storage_owner';
    end if;
    if not has_schema_privilege('adlog_storage_owner','public','CREATE') then
        raise exception 'migration 089 storage owner lacks public schema CREATE';
    end if;
    if exists (
        select 1
        from pg_catalog.pg_namespace n
        cross join lateral pg_catalog.aclexplode(
            coalesce(n.nspacl,pg_catalog.acldefault('n',n.nspowner))
        ) a
        where n.nspname='public' and a.grantee=0 and a.privilege_type='CREATE'
    ) or exists (
        select 1 from pg_catalog.pg_roles r
        where r.rolcanlogin and not r.rolsuper
          and not pg_has_role(r.oid,'adlog_storage_owner','MEMBER')
          and has_schema_privilege(r.oid,'public','CREATE')
    ) then
        raise exception 'migration 089 requires public schema not writable by PUBLIC or untrusted roles';
    end if;
    if to_regclass('public.schema_migrations') is null then
        raise exception 'migration 089 requires schema_migrations';
    end if;
    select count(*) into v_marker_count from public.schema_migrations where version=88;
    if v_marker_count <> 1 or not exists (
        select 1 from public.schema_migrations
        where version=88 and name='source_capture_continuity_declarations'
    ) then
        raise exception 'migration 089 requires migration 088 exact marker';
    end if;
    if exists(select 1 from public.schema_migrations where version>88) then
        raise exception 'migration 089 refuses later migration markers';
    end if;
    if to_regclass('public.events_v2_core') is null
       or to_regclass('public.event_facts_v2') is null
       or to_regclass('public.storage_v2_channel') is null
       or to_regclass('public.normalized_events') is null then
        raise exception 'migration 089 requires hot source identity and facts tables';
    end if;
    if not exists (
        select 1 from pg_class
        where oid='public.event_facts_v2'::regclass
          and pg_get_userbyid(relowner)='adlog_storage_owner'
    ) then
        raise exception 'migration 089 requires storage owner ownership of event_facts_v2';
    end if;
    if not exists(select 1 from pg_extension where extname='pgcrypto') then
        raise exception 'migration 089 requires pgcrypto';
    end if;
    if to_regclass('public.process_episode_revisions') is not null
       or to_regclass('public.process_episode_evidence') is not null
       or to_regprocedure('public.write_process_episode_revision_v89(jsonb)') is not null
       or to_regprocedure('public.process_episode_evidence_reject_mutation()') is not null then
        raise exception 'migration 089 refuses conflicting process episode objects';
    end if;
    if exists (
        select 1 from pg_attribute
        where attrelid='public.event_facts_v2'::regclass and not attisdropped
          and attname=any(array[
            'process_parent_id','process_command_line','process_user_sid',
            'process_user_name','process_user_domain','process_logon_id',
            'service_file','service_account','service_start_type','task_content',
            'task_change','native_process_id'
          ])
    ) then
        raise exception 'migration 089 refuses conflicting event_facts_v2 columns';
    end if;
    if exists (
        select 1 from public.event_facts_v2
        where (process_name is not null and octet_length(process_name)>512)
           or (process_id is not null and (
                not case when process_id ~ '^[1-9][0-9]{0,9}$'
                    then process_id::numeric between 1 and 4294967295 else false end
           ))
           or (powershell_process_id is not null and (
                not case when powershell_process_id ~ '^[1-9][0-9]{0,9}$'
                    then powershell_process_id::numeric between 1 and 4294967295 else false end
           ))
    ) then
        raise exception 'migration 089 existing process identity violates byte/range contract';
    end if;
end
$$;

set local role adlog_storage_owner;

alter table public.event_facts_v2
    drop constraint event_facts_v2_process_name_bounded,
    drop constraint event_facts_v2_process_id_bounded,
    drop constraint event_facts_v2_powershell_process_id_bounded,
    add constraint event_facts_v2_process_name_bounded check (
        process_name is null or octet_length(process_name) <= 512
    ),
    add constraint event_facts_v2_process_id_windows check (
        process_id is null or case when process_id ~ '^[1-9][0-9]{0,9}$'
            then process_id::numeric between 1 and 4294967295 else false end
    ),
    add constraint event_facts_v2_powershell_process_id_windows check (
        powershell_process_id is null or case when powershell_process_id ~ '^[1-9][0-9]{0,9}$'
            then powershell_process_id::numeric between 1 and 4294967295 else false end
    ),
    add column process_parent_id text,
    add column process_command_line text,
    add column process_user_sid text,
    add column process_user_name text,
    add column process_user_domain text,
    add column process_logon_id text,
    add column service_file text,
    add column service_account text,
    add column service_start_type text,
    add column task_content text,
    add column task_change text,
    add column native_process_id text,
    add constraint event_facts_v2_process_parent_id_bounded check (
        process_parent_id is null or case when process_parent_id ~ '^[1-9][0-9]{0,9}$'
            then process_parent_id::numeric between 1 and 4294967295 else false end
    ),
    add constraint event_facts_v2_process_command_line_bounded check (process_command_line is null or octet_length(process_command_line) <= 4096),
    add constraint event_facts_v2_process_user_sid_bounded check (process_user_sid is null or octet_length(process_user_sid) <= 512),
    add constraint event_facts_v2_process_user_name_bounded check (process_user_name is null or octet_length(process_user_name) <= 512),
    add constraint event_facts_v2_process_user_domain_bounded check (process_user_domain is null or octet_length(process_user_domain) <= 512),
    add constraint event_facts_v2_process_logon_id_bounded check (process_logon_id is null or octet_length(process_logon_id) <= 128),
    add constraint event_facts_v2_service_file_bounded check (service_file is null or octet_length(service_file) <= 2048),
    add constraint event_facts_v2_service_account_bounded check (service_account is null or octet_length(service_account) <= 512),
    add constraint event_facts_v2_service_start_type_bounded check (service_start_type is null or octet_length(service_start_type) <= 128),
    add constraint event_facts_v2_task_content_bounded check (task_content is null or octet_length(task_content) <= 8192),
    add constraint event_facts_v2_task_change_bounded check (task_change is null or task_change in ('created','deleted','enabled','disabled','updated')),
    add constraint event_facts_v2_native_process_id_bounded check (
        native_process_id is null or case when native_process_id ~ '^[1-9][0-9]{0,9}$'
            then native_process_id::numeric between 1 and 4294967295 else false end
    );

create table public.process_episode_revisions (
    revision_id uuid primary key,
    episode_id text not null,
    revision_no integer not null check (revision_no > 0),
    assembler_id text not null,
    assembler_version text not null,
    idempotency_key bytea not null unique check (octet_length(idempotency_key)=32),
    revision_sha256 bytea not null check (octet_length(revision_sha256)=32),
    revision_payload text not null check (octet_length(revision_payload) <= 32768),
    evidence_manifest_sha256 bytea not null check (octet_length(evidence_manifest_sha256)=32),
    evidence_manifest_payload text not null check (octet_length(evidence_manifest_payload) <= 131072),
    completeness_state text not null,
    confirmation_state text not null,
    ordering_state text not null,
    domain_id bigint not null check (domain_id > 0),
    source_host_id bigint not null check (source_host_id > 0),
    display_host text not null,
    boot_event_id bigint not null,
    process_id bigint not null check (process_id between 1 and 4294967295),
    start_event_id bigint not null,
    started_at_utc timestamptz not null,
    end_event_id bigint,
    confirmed_end_at_utc timestamptz,
    process_name text,
    parent_process_id bigint check (parent_process_id is null or parent_process_id between 1 and 4294967295),
    parent_episode_id text,
    command_line text,
    user_sid text,
    user_name text,
    user_domain text,
    logon_id text,
    evidence_count smallint not null check (evidence_count between 1 and 256),
    recorded_at timestamptz not null default now(),
    constraint process_episode_identity_unique unique (episode_id,revision_no),
    constraint process_episode_id_digest check (episode_id ~ '^[0-9a-f]{64}$'),
    constraint process_episode_assembler_bounded check (octet_length(assembler_id) between 1 and 128 and octet_length(assembler_version) between 1 and 64),
    constraint process_episode_state_bounded check (
        completeness_state in ('complete','incomplete_open','incomplete_parent_unproven','conflict_ambiguous_close')
        and confirmation_state in ('confirmed_end','open_incomplete','ambiguous_conflict')
        and ordering_state in ('source_native','cross_channel_uncertain')
    ),
    constraint process_episode_identity_bounded check (octet_length(display_host) between 1 and 512),
    constraint process_episode_end_exact check (
        (confirmation_state='confirmed_end' and end_event_id is not null and confirmed_end_at_utc is not null)
        or (confirmation_state<>'confirmed_end' and end_event_id is null and confirmed_end_at_utc is null)
    ),
    constraint process_episode_text_bounded check (
        (process_name is null or octet_length(process_name) <= 512)
        and (parent_episode_id is null or parent_episode_id ~ '^[0-9a-f]{64}$')
        and (command_line is null or octet_length(command_line) <= 4096)
        and (user_sid is null or octet_length(user_sid) <= 512)
        and (user_name is null or octet_length(user_name) <= 512)
        and (user_domain is null or octet_length(user_domain) <= 512)
        and (logon_id is null or octet_length(logon_id) <= 128)
    ),
    constraint process_episode_revision_digest_exact check (
        revision_sha256=public.digest(convert_to(revision_payload,'UTF8'),'sha256')
        and evidence_manifest_sha256=public.digest(convert_to(evidence_manifest_payload,'UTF8'),'sha256')
    ),
    constraint process_episode_idempotency_exact check (
        idempotency_key=public.digest(
            convert_to(episode_id || ':' || assembler_id || ':' || assembler_version || ':','UTF8') || revision_sha256,
            'sha256'
        )
    )
);

create table public.process_episode_evidence (
    revision_id uuid not null references public.process_episode_revisions(revision_id) on delete restrict,
    evidence_order smallint not null check (evidence_order between 0 and 255),
    source_event_id bigint not null,
    evidence_role text not null check (evidence_role in ('boot_scope','start','confirmed_end','attached')),
    semantic_type text not null check (octet_length(semantic_type) between 1 and 160),
    semantic_contract_version integer not null check (semantic_contract_version > 0),
    normalizer_id text not null check (octet_length(normalizer_id) between 1 and 128),
    normalizer_version text not null check (octet_length(normalizer_version) between 1 and 128),
    semantic_sha256 bytea not null check (octet_length(semantic_sha256)=32),
    observed_at_utc timestamptz not null,
    domain_id bigint not null check (domain_id > 0),
    source_host_id bigint not null check (source_host_id > 0),
    source_channel text not null check (octet_length(source_channel) between 1 and 512),
    event_record_id bigint not null check (event_record_id >= 0),
    source_event_sha256 bytea not null check (octet_length(source_event_sha256)=32),
    source_facts_sha256 bytea not null check (octet_length(source_facts_sha256)=32),
    primary key (revision_id,evidence_order),
    unique (revision_id,source_event_id)
);

create index process_episode_identity_time_idx
    on public.process_episode_revisions(domain_id,source_host_id,boot_event_id,process_id,started_at_utc,start_event_id);
create index process_episode_evidence_source_idx
    on public.process_episode_evidence(domain_id,source_host_id,source_channel,event_record_id,source_event_id);

create function public.process_episode_evidence_reject_mutation()
returns trigger language plpgsql set search_path=pg_catalog as $$
begin
    raise exception 'process episode revisions and evidence are append-only';
end
$$;
create trigger process_episode_revisions_immutable
before update or delete on public.process_episode_revisions
for each row execute function public.process_episode_evidence_reject_mutation();
create trigger process_episode_revisions_no_truncate
before truncate on public.process_episode_revisions
for each statement execute function public.process_episode_evidence_reject_mutation();
create trigger process_episode_evidence_immutable
before update or delete on public.process_episode_evidence
for each row execute function public.process_episode_evidence_reject_mutation();
create trigger process_episode_evidence_no_truncate
before truncate on public.process_episode_evidence
for each statement execute function public.process_episode_evidence_reject_mutation();

create function public.write_process_episode_revision_v89(p pg_catalog.jsonb)
returns uuid
language plpgsql
security definer
set search_path=pg_catalog
as $$
declare
    v_revision_id uuid;
    v_expected_revision_id uuid;
    v_expected_episode_id text;
    v_revision_hex text;
    v_derived_ordering_state text;
    v_existing public.process_episode_revisions%rowtype;
    v_state jsonb;
    v_manifest jsonb;
    v_revision_payload text;
    v_manifest_payload text;
    v_revision_sha bytea;
    v_manifest_sha bytea;
    v_idempotency bytea;
    v_evidence_count integer;
    v_next_revision integer;
    v_item jsonb;
    v_expected_manifest jsonb;
begin
    if jsonb_typeof(p)<>'object' then
        raise exception 'process episode writer payload must be an object';
    end if;
    if octet_length(p::text)>524288
       or octet_length(coalesce(p->>'revision_payload',''))>32768
       or octet_length(coalesce(p->>'evidence_manifest_payload',''))>131072 then
        raise exception 'process episode writer payload exceeds byte contract';
    end if;
    if not p ?& array[
        'episode_id','process_id','domain_id','source_host_id','display_host',
        'boot_event_id','start_event_id','started_at_utc','end_event_id',
        'confirmed_end_at_utc','process_name','command_line','user_sid',
        'user_name','user_domain','logon_id','parent_process_id',
        'parent_episode_id','completeness_state','confirmation_state',
        'ordering_state','evidence_count','evidence_manifest_sha256',
        'assembler_id','assembler_version','revision_id','idempotency_key',
        'revision_sha256','revision_payload','evidence_manifest',
        'evidence_manifest_payload'
    ] or (select count(*) from jsonb_object_keys(p))<>31 then
        raise exception 'process episode writer payload shape mismatch';
    end if;
    v_revision_id := (p->>'revision_id')::uuid;
    v_revision_payload := p->>'revision_payload';
    v_manifest_payload := p->>'evidence_manifest_payload';
    v_state := v_revision_payload::jsonb;
    v_manifest := v_manifest_payload::jsonb;
    if jsonb_typeof(v_state)<>'object' or jsonb_typeof(v_manifest)<>'array'
       or v_manifest <> p->'evidence_manifest' then
        raise exception 'process episode revision/evidence payload mismatch';
    end if;
    if p - array[
        'revision_id','idempotency_key','revision_sha256','revision_payload',
        'evidence_manifest','evidence_manifest_payload'
    ] <> v_state then
        raise exception 'process episode writer top-level state mismatch';
    end if;
    if exists (
        select 1 from jsonb_array_elements(v_manifest) item(value)
        where jsonb_typeof(value)<>'object'
           or not value ?& array[
                'evidence_order','source_event_id','evidence_role','semantic_type',
                'observed_at_utc','source_channel','event_record_id',
                'source_event_sha256','source_facts_sha256','domain_id','source_host_id',
                'semantic_contract_version','normalizer_id','normalizer_version',
                'semantic_sha256'
           ]
           or (select count(*) from jsonb_object_keys(value))<>15
    ) then
        raise exception 'process episode evidence object shape mismatch';
    end if;
    v_revision_sha := decode(p->>'revision_sha256','hex');
    v_manifest_sha := decode(v_state->>'evidence_manifest_sha256','hex');
    v_idempotency := decode(p->>'idempotency_key','hex');
    if octet_length(v_revision_sha)<>32 or octet_length(v_manifest_sha)<>32
       or octet_length(v_idempotency)<>32
       or v_revision_sha<>public.digest(convert_to(v_revision_payload,'UTF8'),'sha256')
       or v_manifest_sha<>public.digest(convert_to(v_manifest_payload,'UTF8'),'sha256')
       or v_idempotency<>public.digest(
            convert_to((v_state->>'episode_id') || ':' || (v_state->>'assembler_id') || ':' || (v_state->>'assembler_version') || ':','UTF8') || v_revision_sha,
            'sha256'
       ) then
        raise exception 'process episode revision/evidence digest mismatch';
    end if;
    v_expected_episode_id := encode(public.digest(convert_to(
        '{"boot_event_id":' || (v_state->>'boot_event_id') ||
        ',"domain_id":' || to_jsonb(v_state->>'domain_id')::text ||
        ',"process_id":' || (v_state->>'process_id') ||
        ',"source_host_id":' || to_jsonb(v_state->>'source_host_id')::text ||
        ',"start_event_id":' || (v_state->>'start_event_id') ||
        ',"started_at_utc":' || to_jsonb(v_state->>'started_at_utc')::text || '}',
        'UTF8'
    ),'sha256'),'hex');
    v_revision_hex := encode(public.digest(
        decode('6ba7b8119dad11d180b400c04fd430c8','hex') ||
        convert_to('adlog:process-revision:' || encode(v_idempotency,'hex'),'UTF8'),
        'sha1'
    ),'hex');
    v_revision_hex := substr(v_revision_hex,1,12) || '5' ||
        substr(v_revision_hex,14,3) ||
        to_hex((get_byte(decode(substr(v_revision_hex,17,2),'hex'),0)&63)|128) ||
        substr(v_revision_hex,19,14);
    v_expected_revision_id := (
        substr(v_revision_hex,1,8) || '-' || substr(v_revision_hex,9,4) || '-' ||
        substr(v_revision_hex,13,4) || '-' || substr(v_revision_hex,17,4) || '-' ||
        substr(v_revision_hex,21,12)
    )::uuid;
    if v_state->>'episode_id'<>v_expected_episode_id
       or v_revision_id<>v_expected_revision_id then
        raise exception 'process episode derived identity mismatch';
    end if;
    v_evidence_count := jsonb_array_length(v_manifest);
    if v_evidence_count<>coalesce((v_state->>'evidence_count')::integer,-1)
       or v_evidence_count not between 1 and 256 then
        raise exception 'process episode evidence count mismatch';
    end if;
    if exists (
        select 1 from jsonb_array_elements(v_manifest) with ordinality item(value,ord)
        where (value->>'evidence_order')::integer<>ord-1
           or (value->>'domain_id')::bigint<>(v_state->>'domain_id')::bigint
           or (value->>'source_host_id')::bigint<>(v_state->>'source_host_id')::bigint
    ) or (
        select count(distinct (value->>'source_event_id')::bigint)
        from jsonb_array_elements(v_manifest) item(value)
    )<>v_evidence_count then
        raise exception 'process episode evidence membership/provenance mismatch';
    end if;
    if (
        select count(*) from jsonb_array_elements(v_manifest) item(value)
        where value->>'evidence_role'='boot_scope'
    )<>1 or (
        select count(*) from jsonb_array_elements(v_manifest) item(value)
        where value->>'evidence_role'='boot_scope'
          and value->>'semantic_type'='system.boot.boundary'
          and (value->>'source_event_id')::bigint=(v_state->>'boot_event_id')::bigint
    )<>1 then
        raise exception 'process episode boot evidence mismatch';
    end if;
    select case when count(distinct lower(value->>'source_channel'))>1
        then 'cross_channel_uncertain' else 'source_native' end
    into v_derived_ordering_state
    from jsonb_array_elements(v_manifest) item(value);
    if v_state->>'ordering_state'<>v_derived_ordering_state then
        raise exception 'process episode derived ordering mismatch';
    end if;
    if (
        select count(*) from jsonb_array_elements(v_manifest) item(value)
        where value->>'evidence_role'='start'
    )<>1 or (
        select count(*) from jsonb_array_elements(v_manifest) item(value)
        where value->>'evidence_role'='start'
          and (value->>'source_event_id')::bigint=(v_state->>'start_event_id')::bigint
          and (value->>'observed_at_utc')::timestamptz=(v_state->>'started_at_utc')::timestamptz
    )<>1 then
        raise exception 'process episode start evidence mismatch';
    end if;
    if (v_state->>'end_event_id') is null then
        if exists(select 1 from jsonb_array_elements(v_manifest) item(value) where value->>'evidence_role'='confirmed_end') then
            raise exception 'process episode end evidence mismatch';
        end if;
    elsif (
        select count(*) from jsonb_array_elements(v_manifest) item(value)
        where value->>'evidence_role'='confirmed_end'
    )<>1 or (
        select count(*) from jsonb_array_elements(v_manifest) item(value)
        where value->>'evidence_role'='confirmed_end'
          and (value->>'source_event_id')::bigint=(v_state->>'end_event_id')::bigint
          and (value->>'observed_at_utc')::timestamptz=(v_state->>'confirmed_end_at_utc')::timestamptz
    )<>1 then
        raise exception 'process episode end evidence mismatch';
    end if;

    -- An exact replay remains verifiable from the immutable durable manifest
    -- after the seven-day hot source window has expired.  New revisions still
    -- require the authoritative hot-source validation below.
    perform pg_advisory_xact_lock(hashtextextended(v_state->>'episode_id',0));
    select * into v_existing from public.process_episode_revisions where idempotency_key=v_idempotency;
    if found then
        select jsonb_agg(jsonb_build_object(
            'evidence_order',e.evidence_order,
            'source_event_id',e.source_event_id,
            'evidence_role',e.evidence_role,
            'semantic_type',e.semantic_type,
            'semantic_contract_version',e.semantic_contract_version,
            'normalizer_id',e.normalizer_id,
            'normalizer_version',e.normalizer_version,
            'semantic_sha256',encode(e.semantic_sha256,'hex'),
            'observed_at_utc',m.value->>'observed_at_utc',
            'source_channel',e.source_channel,
            'event_record_id',e.event_record_id,
            'source_event_sha256',encode(e.source_event_sha256,'hex'),
            'source_facts_sha256',encode(e.source_facts_sha256,'hex'),
            'domain_id',e.domain_id,
            'source_host_id',e.source_host_id
        ) order by e.evidence_order) into v_expected_manifest
        from public.process_episode_evidence e
        join jsonb_array_elements(v_manifest) m(value)
          on (m.value->>'evidence_order')::integer=e.evidence_order
        where e.revision_id=v_existing.revision_id
          and (m.value->>'observed_at_utc')::timestamptz=e.observed_at_utc;
        if v_existing.revision_id<>v_revision_id
           or v_existing.revision_sha256<>v_revision_sha
           or v_existing.revision_payload<>v_revision_payload
           or v_existing.evidence_manifest_payload<>v_manifest_payload
           or (select count(*) from public.process_episode_evidence where revision_id=v_existing.revision_id)<>v_evidence_count
           or coalesce(v_expected_manifest,'[]'::jsonb)<>v_manifest then
            raise exception 'process episode evidence replay conflict';
        end if;
        return v_existing.revision_id;
    end if;

    -- Validate caller-supplied identity/provenance only.  This deliberately
    -- does not infer process membership: the single semantic worker remains
    -- the only component that assembles an episode.
    if exists (
        select 1
        from jsonb_array_elements(v_manifest) item(value)
        left join public.events_v2_core source
          on source.id=(item.value->>'source_event_id')::integer
        left join public.event_facts_v2 facts on facts.event_id=source.id
        left join public.storage_v2_channel channel on channel.id=source.channel_id
        where item.value->>'source_event_id' is null
           or item.value->>'semantic_type' is null
           or item.value->>'observed_at_utc' is null
           or item.value->>'domain_id' is null
           or item.value->>'source_host_id' is null
           or item.value->>'source_channel' is null
           or item.value->>'event_record_id' is null
           or item.value->>'source_event_sha256' is null
           or item.value->>'source_facts_sha256' is null
           or source.id is null
           or facts.event_id is null
           or channel.id is null
           or source.domain_id<>(item.value->>'domain_id')::bigint
           or source.server_id<>(item.value->>'source_host_id')::bigint
           or source.time_created_utc<>(item.value->>'observed_at_utc')::timestamptz
           or channel.value<>(item.value->>'source_channel')
           or source.event_record_id is null
           or source.event_record_id<>(item.value->>'event_record_id')::bigint
           or source.normalized_hash<>decode(item.value->>'source_event_sha256','hex')
           or facts.source_facts_sha256<>decode(item.value->>'source_facts_sha256','hex')
           or (
                select count(*) from public.normalized_events normalized
                where normalized.source_event_id=source.id
                  and normalized.processing_status='normalized'
                  and normalized.semantic_type=item.value->>'semantic_type'
                  and normalized.semantic_contract_version=(item.value->>'semantic_contract_version')::integer
                  and normalized.normalizer_id=item.value->>'normalizer_id'
                  and normalized.normalizer_version=item.value->>'normalizer_version'
                  and normalized.semantic_sha256=decode(item.value->>'semantic_sha256','hex')
                  and normalized.occurred_at_utc=source.time_created_utc
                  and normalized.source_event_sha256=source.normalized_hash
           )<>1
    ) then
        raise exception 'process episode evidence does not match authoritative hot source';
    end if;

    select coalesce(max(revision_no),0)+1 into v_next_revision
    from public.process_episode_revisions where episode_id=v_state->>'episode_id';
    insert into public.process_episode_revisions(
        revision_id,episode_id,revision_no,assembler_id,assembler_version,
        idempotency_key,revision_sha256,revision_payload,evidence_manifest_sha256,
        evidence_manifest_payload,completeness_state,confirmation_state,
        ordering_state,domain_id,source_host_id,display_host,boot_event_id,
        process_id,start_event_id,started_at_utc,end_event_id,confirmed_end_at_utc,
        process_name,parent_process_id,parent_episode_id,command_line,user_sid,
        user_name,user_domain,logon_id,evidence_count
    ) values(
        v_revision_id,v_state->>'episode_id',v_next_revision,v_state->>'assembler_id',
        v_state->>'assembler_version',v_idempotency,v_revision_sha,v_revision_payload,
        v_manifest_sha,v_manifest_payload,v_state->>'completeness_state',
        v_state->>'confirmation_state',v_state->>'ordering_state',
        (v_state->>'domain_id')::bigint,(v_state->>'source_host_id')::bigint,
        v_state->>'display_host',(v_state->>'boot_event_id')::bigint,
        (v_state->>'process_id')::bigint,(v_state->>'start_event_id')::bigint,
        (v_state->>'started_at_utc')::timestamptz,
        (v_state->>'end_event_id')::bigint,
        (v_state->>'confirmed_end_at_utc')::timestamptz,
        v_state->>'process_name',(v_state->>'parent_process_id')::bigint,
        v_state->>'parent_episode_id',v_state->>'command_line',v_state->>'user_sid',
        v_state->>'user_name',v_state->>'user_domain',v_state->>'logon_id',
        v_evidence_count
    );
    for v_item in select value from jsonb_array_elements(v_manifest) item(value) loop
        insert into public.process_episode_evidence(
            revision_id,evidence_order,source_event_id,evidence_role,semantic_type,
            semantic_contract_version,normalizer_id,normalizer_version,semantic_sha256,
            observed_at_utc,domain_id,source_host_id,source_channel,event_record_id,
            source_event_sha256,source_facts_sha256
        ) values(
            v_revision_id,(v_item->>'evidence_order')::smallint,
            (v_item->>'source_event_id')::bigint,v_item->>'evidence_role',
            v_item->>'semantic_type',(v_item->>'semantic_contract_version')::integer,
            v_item->>'normalizer_id',v_item->>'normalizer_version',
            decode(v_item->>'semantic_sha256','hex'),
            (v_item->>'observed_at_utc')::timestamptz,
            (v_item->>'domain_id')::bigint,(v_item->>'source_host_id')::bigint,
            v_item->>'source_channel',(v_item->>'event_record_id')::bigint,
            decode(v_item->>'source_event_sha256','hex'),
            decode(v_item->>'source_facts_sha256','hex')
        );
    end loop;
    return v_revision_id;
end
$$;

revoke all on table public.process_episode_revisions,public.process_episode_evidence from public,adlog_semantic_worker;
grant select on table public.process_episode_revisions,public.process_episode_evidence to adlog_semantic_worker;
revoke all on function public.write_process_episode_revision_v89(pg_catalog.jsonb) from public;
grant execute on function public.write_process_episode_revision_v89(pg_catalog.jsonb) to adlog_semantic_worker;

insert into public.schema_migrations(version,name)
values (89,'process_activity_foundation');
commit;
