-- Stage 10 unified immutable administrative activity journal foundation.
-- This does not backfill or replace the specialized auth/access audit tables.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_administrative_activity_v66')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 066 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=63 and name='radius_vpn_operations_read_boundary'
    ) then
        raise exception 'migration 066 requires core schema migration 063';
    end if;
    if to_regrole('adlog_administrative_activity_owner') is not null then
        raise exception 'migration 066 requires absent administrative activity owner role';
    end if;
    if to_regclass('administrative_activity_v1') is not null then
        raise exception 'migration 066 requires absent administrative activity table';
    end if;
end
$$;

create role adlog_administrative_activity_owner
    noinherit nologin nosuperuser nocreatedb nocreaterole
    nobypassrls noreplication;
grant adlog_administrative_activity_owner to adlog_storage_owner;

create table administrative_activity_v1 (
    activity_id bigint generated always as identity primary key,
    event_uid uuid not null unique,
    occurred_at_utc timestamptz not null,
    recorded_at_utc timestamptz not null default clock_timestamp(),
    actor_kind text not null
        check (actor_kind in ('session','api_key','windows','system','local_operator','plugin')),
    actor_key text not null
        check (btrim(actor_key) <> '' and length(actor_key) <= 200),
    category text not null
        check (category in (
            'authentication','plugin_lifecycle','source_configuration',
            'access_management','report_publication','manual_operation'
        )),
    action_key text not null
        check (action_key ~ '^[a-z][a-z0-9_.-]{0,119}$'),
    target_kind text
        check (target_kind is null or target_kind ~ '^[a-z][a-z0-9_.-]{0,79}$'),
    target_key text
        check (target_key is null or length(target_key) <= 240),
    outcome text not null
        check (outcome in ('started','succeeded','failed','denied','stopped','cancelled')),
    reason_code text
        check (reason_code is null or reason_code ~ '^[a-z][a-z0-9_.-]{0,119}$'),
    details_json jsonb not null default '{}'::jsonb
        check (jsonb_typeof(details_json)='object')
        check (octet_length(details_json::text) <= 8192),
    remote_address inet,
    correlation_id uuid,
    content_hash bytea not null check (octet_length(content_hash)=32),
    previous_record_hash bytea not null check (octet_length(previous_record_hash)=32),
    record_hash bytea not null unique check (octet_length(record_hash)=32)
);

create index administrative_activity_occurred_idx
    on administrative_activity_v1(occurred_at_utc desc,activity_id desc);
create index administrative_activity_category_idx
    on administrative_activity_v1(category,occurred_at_utc desc,activity_id desc);

create function reject_administrative_activity_mutation_v1()
returns trigger
language plpgsql
set search_path = pg_catalog, public
as $$
begin
    raise exception 'administrative activity journal is append-only';
end
$$;

create trigger administrative_activity_reject_update_delete
before update or delete on administrative_activity_v1
for each row execute function reject_administrative_activity_mutation_v1();

create trigger administrative_activity_reject_truncate
before truncate on administrative_activity_v1
for each statement execute function reject_administrative_activity_mutation_v1();

create function append_administrative_activity_v1(
    p_event_uid uuid,
    p_occurred_at_utc timestamptz,
    p_actor_kind text,
    p_actor_key text,
    p_category text,
    p_action_key text,
    p_target_kind text,
    p_target_key text,
    p_outcome text,
    p_reason_code text,
    p_details_json jsonb,
    p_remote_address inet,
    p_correlation_id uuid
)
returns table(activity_id bigint, record_hash bytea)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
    v_content jsonb;
    v_content_hash bytea;
    v_previous_hash bytea;
    v_existing_content_hash bytea;
    v_existing_record_hash bytea;
    v_existing_activity_id bigint;
    v_record_hash bytea;
begin
    if p_event_uid is null or p_occurred_at_utc is null then
        raise exception 'administrative activity identity and time are required';
    end if;
    if p_actor_kind not in ('session','api_key','windows','system','local_operator','plugin')
       or btrim(coalesce(p_actor_key,''))=''
       or length(p_actor_key)>200 then
        raise exception 'administrative activity actor is invalid';
    end if;
    if p_category not in (
        'authentication','plugin_lifecycle','source_configuration',
        'access_management','report_publication','manual_operation'
    ) or p_action_key !~ '^[a-z][a-z0-9_.-]{0,119}$' then
        raise exception 'administrative activity category or action is invalid';
    end if;
    if p_outcome not in ('started','succeeded','failed','denied','stopped','cancelled') then
        raise exception 'administrative activity outcome is invalid';
    end if;
    if jsonb_typeof(coalesce(p_details_json,'{}'::jsonb)) <> 'object'
       or octet_length(coalesce(p_details_json,'{}'::jsonb)::text) > 8192
       or exists (
           select 1
           from jsonb_each(coalesce(p_details_json,'{}'::jsonb)) as detail(key,value)
           where jsonb_typeof(detail.value) not in ('string','number','boolean','null')
              or detail.key ~* '(password|secret|token|dsn|credential|payload|raw)'
       ) then
        raise exception 'administrative activity details are unsafe';
    end if;

    v_content := jsonb_build_object(
        'event_uid',p_event_uid::text,
        'occurred_at_utc',to_char(p_occurred_at_utc at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US'),
        'actor_kind',p_actor_kind,
        'actor_key',p_actor_key,
        'category',p_category,
        'action_key',p_action_key,
        'target_kind',p_target_kind,
        'target_key',p_target_key,
        'outcome',p_outcome,
        'reason_code',p_reason_code,
        'details_json',coalesce(p_details_json,'{}'::jsonb),
        'remote_address',p_remote_address::text,
        'correlation_id',p_correlation_id::text
    );
    v_content_hash := sha256(convert_to(v_content::text,'UTF8'));

    perform pg_advisory_xact_lock(
        hashtext('ad_log_reports_administrative_activity_append_v1')
    );

    select current.content_hash,current.record_hash,current.activity_id
    into v_existing_content_hash,v_existing_record_hash,v_existing_activity_id
    from public.administrative_activity_v1 as current
    where current.event_uid=p_event_uid;
    if found then
        if v_existing_content_hash<>v_content_hash then
            raise exception 'administrative activity idempotency conflict';
        end if;
        return query select v_existing_activity_id,v_existing_record_hash;
        return;
    end if;

    select current.record_hash
    into v_previous_hash
    from public.administrative_activity_v1 as current
    order by current.activity_id desc
    limit 1;
    v_previous_hash := coalesce(v_previous_hash,decode(repeat('00',32),'hex'));
    v_record_hash := sha256(v_previous_hash || v_content_hash);

    insert into public.administrative_activity_v1(
        event_uid,occurred_at_utc,actor_kind,actor_key,category,action_key,
        target_kind,target_key,outcome,reason_code,details_json,remote_address,
        correlation_id,content_hash,previous_record_hash,record_hash
    ) values (
        p_event_uid,p_occurred_at_utc,p_actor_kind,p_actor_key,p_category,p_action_key,
        p_target_kind,p_target_key,p_outcome,p_reason_code,
        coalesce(p_details_json,'{}'::jsonb),p_remote_address,p_correlation_id,
        v_content_hash,v_previous_hash,v_record_hash
    ) returning administrative_activity_v1.activity_id
    into v_existing_activity_id;
    return query select v_existing_activity_id,v_record_hash;
end
$$;

revoke all on table administrative_activity_v1 from public,adlog_user;
revoke all on sequence administrative_activity_v1_activity_id_seq from public,adlog_user;
revoke all on function reject_administrative_activity_mutation_v1() from public,adlog_user;
revoke all on function append_administrative_activity_v1(
    uuid,timestamptz,text,text,text,text,text,text,text,text,jsonb,inet,uuid
) from public;
grant execute on function append_administrative_activity_v1(
    uuid,timestamptz,text,text,text,text,text,text,text,text,jsonb,inet,uuid
) to adlog_user;

-- PostgreSQL requires the future object owner to have CREATE on the containing
-- schema while ownership is transferred. Keep USAGE for function execution,
-- but remove CREATE again before commit.
grant usage,create on schema public
    to adlog_administrative_activity_owner;

alter table administrative_activity_v1
    owner to adlog_administrative_activity_owner;
alter function reject_administrative_activity_mutation_v1()
    owner to adlog_administrative_activity_owner;
alter function append_administrative_activity_v1(
    uuid,timestamptz,text,text,text,text,text,text,text,text,jsonb,inet,uuid
) owner to adlog_administrative_activity_owner;

revoke create on schema public
    from adlog_administrative_activity_owner;

insert into schema_migrations(version,name)
values (66,'administrative_activity_journal')
on conflict(version) do update set name=excluded.name;

commit;
