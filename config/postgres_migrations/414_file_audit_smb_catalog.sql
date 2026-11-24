begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_file_audit_smb_catalog414'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=410 and name='password_origin_prefix')
       or exists(select 1 from public.schema_migrations where version>=414) then
        raise exception 'file_audit_smb_catalog414_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
create table public.sli_file_audit_smb_catalog (
    agent_id uuid primary key references public.sli_agents(id) on delete cascade,
    source_id text not null check(length(source_id) between 1 and 256),
    supported_until timestamptz not null,
    request_id uuid,
    expires_at timestamptz,
    result_status text check(result_status in ('ready','unavailable','incomplete')),
    native_status bigint check(native_status between 1 and 4294967295),
    shares jsonb not null default '[]'::jsonb,
    check((request_id is null)=(expires_at is null)),
    check(request_id is not null or result_status is null),
    check(native_status is null or (result_status is not null and result_status in ('unavailable','incomplete'))),
    check(jsonb_typeof(shares)='array' and jsonb_array_length(shares)<=128),
    check(result_status is not distinct from 'ready' or shares='[]'::jsonb)
);
revoke all on public.sli_file_audit_smb_catalog from public;
grant select,insert,update on public.sli_file_audit_smb_catalog to adlog_user;
reset role;
set local role adlog_file_audit_owner;
create function sli_plugin_file_audit.catalog_policy_matches(uuid,text,bigint,jsonb)
returns boolean language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select exists(select 1 from sli_plugin_file_audit.policy_revisions p
        where p.agent_id=$1 and p.source_instance_id=$2 and p.revision=$3 and p.policy=$4)
$$;
revoke all on function sli_plugin_file_audit.catalog_policy_matches(uuid,text,bigint,jsonb) from public;
grant execute on function sli_plugin_file_audit.catalog_policy_matches(uuid,text,bigint,jsonb) to adlog_user;
reset role;
insert into public.schema_migrations(version,name) values(414,'file_audit_smb_catalog');
commit;
