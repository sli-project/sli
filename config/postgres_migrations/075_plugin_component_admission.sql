-- Durable admission leases for the two disabled remote-access worker cells.
-- This migration does not enable runtime, contact a source or control process.
begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_admission_v75'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 075 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=74 and name='plugin_bundled_install_executor'
    ) then
        raise exception 'migration 075 requires migration 074';
    end if;
    if to_regclass('public.plugin_component_admission_v1') is not null
       or to_regclass('public.plugin_component_leases_v1') is not null
       or to_regprocedure(
         'public.acquire_plugin_component_lease_v1(uuid,text,text,text,text)'
       ) is not null
       or to_regprocedure(
         'public.release_plugin_component_lease_v1(uuid,text,text)'
       ) is not null then
        raise exception 'migration 075 requires absent admission objects';
    end if;
end
$$;

create table plugin_component_admission_v1 (
    plugin_id text not null
        references plugin_installations_v1(plugin_id),
    component_id text not null
        check (component_id in (
            'radius-acquisition','radius-session-observation'
        )),
    admission_mode text not null
        check (admission_mode in ('closed','open','drain_only')),
    revision bigint not null default 1 check (revision >= 1),
    updated_at_utc timestamptz not null default now(),
    primary key(plugin_id,component_id),
    check (
        component_id<>'radius-acquisition'
        or admission_mode<>'drain_only'
    )
);

create table plugin_component_leases_v1 (
    lease_uid uuid primary key,
    plugin_id text not null,
    component_id text not null,
    lease_kind text not null
        check (lease_kind in ('source_contact','delivery_claim')),
    admission_mode_at_acquire text not null
        check (admission_mode_at_acquire in ('open','drain_only')),
    holder_key text not null
        check (btrim(holder_key)<>'' and length(holder_key)<=200),
    acquired_at_utc timestamptz not null default now(),
    expires_at_utc timestamptz not null,
    released_at_utc timestamptz,
    release_outcome text
        check (release_outcome is null or release_outcome in (
            'completed','failed','cancelled','expired'
        )),
    foreign key(plugin_id,component_id)
        references plugin_component_admission_v1(plugin_id,component_id),
    check (
        expires_at_utc>acquired_at_utc
        and expires_at_utc<=acquired_at_utc+interval '120 seconds'
    ),
    check (
        (released_at_utc is null and release_outcome is null)
        or
        (released_at_utc is not null and release_outcome is not null)
    ),
    check (
        (component_id='radius-acquisition' and lease_kind='source_contact')
        or
        (component_id='radius-session-observation'
         and lease_kind='delivery_claim')
    )
);

create unique index plugin_component_one_active_lease_v1
on plugin_component_leases_v1(plugin_id,component_id)
where released_at_utc is null;

insert into plugin_component_admission_v1(
    plugin_id,component_id,admission_mode
) values
    ('sli.remote-access','radius-acquisition','closed'),
    ('sli.remote-access','radius-session-observation','closed');

create function acquire_plugin_component_lease_v1(
    p_lease_uid uuid,
    p_plugin_id text,
    p_component_id text,
    p_lease_kind text,
    p_holder_key text
)
returns table(
    lease_uid uuid,
    component_id text,
    admission_mode text,
    expires_at_utc timestamptz
)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
    v_plugin plugin_installations_v1%rowtype;
    v_component plugin_component_admission_v1%rowtype;
    v_existing plugin_component_leases_v1%rowtype;
    v_now timestamptz := clock_timestamp();
begin
    if p_lease_uid is null
       or p_plugin_id<>'sli.remote-access'
       or p_component_id not in (
         'radius-acquisition','radius-session-observation'
       )
       or p_lease_kind not in ('source_contact','delivery_claim')
       or btrim(coalesce(p_holder_key,''))=''
       or length(p_holder_key)>200 then
        raise exception 'plugin component lease request is invalid';
    end if;
    if p_component_id='radius-acquisition' then
        if p_lease_kind<>'source_contact'
           or not pg_has_role(
             session_user,'adlog_radius_accounting_worker','MEMBER'
           ) then
            raise exception 'plugin acquisition lease caller is invalid';
        end if;
    elsif p_lease_kind<>'delivery_claim'
       or not pg_has_role(
         session_user,'adlog_radius_session_consumer','MEMBER'
       ) then
        raise exception 'plugin consumer lease caller is invalid';
    end if;

    select current.* into v_existing
    from plugin_component_leases_v1 current
    where current.lease_uid=p_lease_uid;
    if found then
        if v_existing.plugin_id<>p_plugin_id
           or v_existing.component_id<>p_component_id
           or v_existing.lease_kind<>p_lease_kind
           or v_existing.holder_key<>p_holder_key then
            raise exception 'plugin component lease idempotency conflict';
        end if;
        return query select v_existing.lease_uid,v_existing.component_id,
            v_existing.admission_mode_at_acquire,
            v_existing.expires_at_utc;
        return;
    end if;

    select current.* into v_plugin
    from plugin_installations_v1 current
    where current.plugin_id=p_plugin_id
    for key share;
    select current.* into v_component
    from plugin_component_admission_v1 current
    where current.plugin_id=p_plugin_id
      and current.component_id=p_component_id
    for update;
    if not found or v_plugin.package_lifecycle<>'registered' then
        raise exception 'plugin component admission state is unavailable';
    end if;

    update plugin_component_leases_v1 current
    set released_at_utc=current.expires_at_utc,
        release_outcome='expired'
    where current.plugin_id=p_plugin_id
      and current.component_id=p_component_id
      and current.released_at_utc is null
      and current.expires_at_utc<=v_now;

    if p_component_id='radius-acquisition' then
        if v_plugin.desired_activation<>'enabled_manual'
           or v_plugin.component_runtime<>'running'
           or v_component.admission_mode<>'open' then
            raise exception 'plugin acquisition admission is closed';
        end if;
    elsif not (
        (
          v_plugin.desired_activation='enabled_manual'
          and v_plugin.component_runtime='running'
          and v_component.admission_mode='open'
        )
        or
        (
          v_plugin.desired_activation='disabled'
          and v_plugin.component_runtime='draining'
          and v_component.admission_mode='drain_only'
        )
    ) then
        raise exception 'plugin consumer admission is closed';
    end if;

    insert into plugin_component_leases_v1(
        lease_uid,plugin_id,component_id,lease_kind,holder_key,
        admission_mode_at_acquire,acquired_at_utc,expires_at_utc
    ) values (
        p_lease_uid,p_plugin_id,p_component_id,p_lease_kind,p_holder_key,
        v_component.admission_mode,v_now,v_now+interval '120 seconds'
    );
    return query select p_lease_uid,p_component_id,
        v_component.admission_mode,v_now+interval '120 seconds';
end
$$;

create function release_plugin_component_lease_v1(
    p_lease_uid uuid,
    p_holder_key text,
    p_outcome text
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
    v_lease plugin_component_leases_v1%rowtype;
begin
    if p_lease_uid is null
       or btrim(coalesce(p_holder_key,''))=''
       or length(p_holder_key)>200
       or p_outcome not in ('completed','failed','cancelled') then
        raise exception 'plugin component lease release is invalid';
    end if;
    select current.* into v_lease
    from plugin_component_leases_v1 current
    where current.lease_uid=p_lease_uid
    for update;
    if not found or v_lease.holder_key<>p_holder_key then
        raise exception 'plugin component lease release mismatch';
    end if;
    if v_lease.component_id='radius-acquisition' then
        if not pg_has_role(
          session_user,'adlog_radius_accounting_worker','MEMBER'
        ) then
            raise exception 'plugin acquisition release caller is invalid';
        end if;
    elsif not pg_has_role(
      session_user,'adlog_radius_session_consumer','MEMBER'
    ) then
        raise exception 'plugin consumer release caller is invalid';
    end if;
    if v_lease.released_at_utc is not null then
        if v_lease.release_outcome<>p_outcome then
            raise exception 'plugin component lease release conflict';
        end if;
        return false;
    end if;
    update plugin_component_leases_v1 current
    set released_at_utc=clock_timestamp(),release_outcome=p_outcome
    where current.lease_uid=p_lease_uid
      and current.released_at_utc is null;
    return true;
end
$$;

revoke all on table plugin_component_admission_v1 from public,adlog_user;
revoke all on table plugin_component_leases_v1 from public,adlog_user;
revoke all on function acquire_plugin_component_lease_v1(
    uuid,text,text,text,text
) from public,adlog_user;
revoke all on function release_plugin_component_lease_v1(
    uuid,text,text
) from public,adlog_user;

grant execute on function acquire_plugin_component_lease_v1(
    uuid,text,text,text,text
) to adlog_radius_accounting_worker,adlog_radius_session_consumer;
grant execute on function release_plugin_component_lease_v1(
    uuid,text,text
) to adlog_radius_accounting_worker,adlog_radius_session_consumer;

grant usage,create on schema public to adlog_plugin_lifecycle_owner;
alter table plugin_component_admission_v1
    owner to adlog_plugin_lifecycle_owner;
alter table plugin_component_leases_v1
    owner to adlog_plugin_lifecycle_owner;
alter function acquire_plugin_component_lease_v1(
    uuid,text,text,text,text
) owner to adlog_plugin_lifecycle_owner;
alter function release_plugin_component_lease_v1(
    uuid,text,text
) owner to adlog_plugin_lifecycle_owner;
revoke create on schema public from adlog_plugin_lifecycle_owner;

insert into schema_migrations(version,name)
values(75,'plugin_component_admission')
on conflict(version) do update set name=excluded.name;

commit;
