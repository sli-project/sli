begin;
select pg_advisory_xact_lock(hashtext('sli_file_audit_activity458'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=455 and name='account_detection_pending')
       or exists(select 1 from public.schema_migrations where version>=458) then
        raise exception 'file_audit_activity458_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- A final receipt may prove a scan whose root appeared on page zero. Require
-- the entire earlier prefix of this scan under the same source and command.
create function public.file_audit_scan_prefix458(
    p_agent uuid,p_scope text,p_scan uuid,p_page integer,p_observed timestamptz)
returns boolean language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    with pages as (
        select h.snapshot,(h.snapshot->>'page_number')::integer as page,h.unread_objects,r->>'path' as root
        from public.sli_agents a
        cross join lateral jsonb_array_elements(a.file_audit#>'{request,config,roots}') r
        join sli_plugin_file_audit.access_snapshots h on h.agent_id=a.id
            and h.source_instance_id=coalesce(a.source_host_id,a.host_id)::text
            and h.collection_scope_id=p_scope
        where a.id=p_agent and a.status='active' and r->>'collection_scope_id'=p_scope
          and a.file_audit#>'{request,command,collection_scope_ids}' ? p_scope
          and a.file_audit#>>'{request,command,policy_revision}'=h.snapshot->>'policy_revision'
          and h.observed_at<=p_observed and h.snapshot->>'scan_id'=p_scan::text
          and (h.snapshot->>'page_number')::integer<p_page
    )
    select p_page between 1 and 100000 and count(*)=p_page and count(distinct page)=p_page
        and coalesce(bool_and((page>=0 and unread_objects=0
            and snapshot->'has_more'='true'::jsonb and snapshot#>'{share,complete}'='true'::jsonb
            and snapshot#>'{local_groups,complete}'='true'::jsonb
            and not exists(select 1 from jsonb_array_elements(snapshot->'objects') o
                where o->'sacl_missing'='true'::jsonb)) is true),false)
        and coalesce(bool_or(page=0 and exists(
            select 1 from jsonb_array_elements(snapshot->'objects') o where o->>'path'=root
                and o->>'object_type'='directory')),false)
    from pages;
$$;
revoke all on function public.file_audit_scan_prefix458(uuid,text,uuid,integer,timestamptz) from public;
grant execute on function public.file_audit_scan_prefix458(uuid,text,uuid,integer,timestamptz) to adlog_user;

insert into public.schema_migrations(version,name) values(458,'file_audit_activity');
reset role;
commit;
