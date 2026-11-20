-- Sigma stage 17: dormant registration and lifecycle admission for one chain.
begin;
select pg_advisory_xact_lock(hashtext('sli_sigma_chain_plugins_v221'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=220 and name='detection_match_risk')
       or exists(select 1 from public.schema_migrations where version>=221) then
        raise exception 'migration 221 prerequisites failed';
    end if;
end $$;

set local role adlog_plugin_lifecycle_owner;
-- Installation contributes draft candidates only. Admission remains explicit.
insert into public.plugin_installations_v1(
    plugin_id,manifest_id,manifest_sha256,package_version,package_lifecycle,
    desired_activation,observed_health,component_runtime,queue_state,revision,immutable_evidence_count)
values('sli.sigma','sli.sigma.package.v3','259495edc8aa3bbb5eb7ce080555edfe66c9302167c845fec8a17514725b9674',
       '1.0.0','registered','disabled','unknown','stopped','drained',1,1)
on conflict(plugin_id) do nothing;
insert into public.plugin_state_v1(plugin_id,configured) values('sli.sigma',true)
on conflict(plugin_id) do nothing;
reset role;

grant create on schema public to adlog_plugin_lifecycle_owner;
set local role adlog_plugin_lifecycle_owner;
create function public.read_sigma_chain_plugin_states_v1()
returns table(plugin_id text,package_version text,installed boolean,configured boolean,
              enabled boolean,component_runtime text)
language sql security definer set search_path=pg_catalog,pg_temp
as $$
    select i.plugin_id,i.package_version,i.package_lifecycle='registered',
           coalesce(s.configured,false),i.desired_activation='enabled_manual',i.component_runtime
    from public.plugin_installations_v1 i
    left join public.plugin_state_v1 s on s.plugin_id=i.plugin_id
    where i.plugin_id in ('sli.ad','sli.sigma')
    order by i.plugin_id
    for share of i;
$$;
revoke all on function public.read_sigma_chain_plugin_states_v1() from public;
grant execute on function public.read_sigma_chain_plugin_states_v1() to adlog_semantic_worker;
reset role;
revoke create on schema public from adlog_plugin_lifecycle_owner;

insert into public.schema_migrations(version,name) values(221,'sigma_chain_plugins');
commit;
