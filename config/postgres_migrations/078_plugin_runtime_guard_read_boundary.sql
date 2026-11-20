-- Least-privilege read boundary used only by the plugin process guard.
begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_runtime_guard_read_boundary_v78'));

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=75 and name='plugin_component_admission'
    ) then
        raise exception 'migration 078 requires migration 075';
    end if;
    if to_regprocedure(
        'public.read_plugin_component_runtime_guard_v1(text,text)'
    ) is not null then
        raise exception 'migration 078 requires absent guard reader';
    end if;
end
$$;

create function read_plugin_component_runtime_guard_v1(
    p_plugin_id text,
    p_component_id text
)
returns table(
    desired_activation text,
    component_runtime text,
    admission_mode text
)
language plpgsql stable security definer
set search_path = pg_catalog, public
as $$
begin
    if p_plugin_id<>'sli.remote-access'
       or p_component_id not in (
         'radius-acquisition','radius-session-observation'
       ) then
        raise exception 'plugin runtime guard scope is invalid';
    end if;
    return query
    select installation.desired_activation,
           installation.component_runtime,
           admission.admission_mode
    from public.plugin_installations_v1 installation
    join public.plugin_component_admission_v1 admission
      on admission.plugin_id=installation.plugin_id
    where installation.plugin_id=p_plugin_id
      and admission.component_id=p_component_id;
    if not found then
        raise exception 'plugin runtime guard state is unavailable';
    end if;
end
$$;

revoke all on function read_plugin_component_runtime_guard_v1(text,text)
    from public,adlog_user;
grant execute on function read_plugin_component_runtime_guard_v1(text,text)
    to adlog_user;
alter function read_plugin_component_runtime_guard_v1(text,text)
    owner to adlog_plugin_lifecycle_owner;

insert into schema_migrations(version,name)
values(78,'plugin_runtime_guard_read_boundary')
on conflict(version) do update set name=excluded.name;

commit;
