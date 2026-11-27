begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_file_audit_catalog_cache457'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=455 and name='account_detection_pending')
       or exists(select 1 from public.schema_migrations where version>=457) then
        raise exception 'file_audit_catalog_cache457_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- An enumeration request and the last accepted catalog have independent lifetimes.
alter table public.sli_file_audit_smb_catalog
    add column cached_shares jsonb not null default '[]'::jsonb,
    add column cached_at timestamptz,
    add constraint file_audit_catalog_cache457_check check (
        jsonb_typeof(cached_shares)='array' and jsonb_array_length(cached_shares)<=128
        and (cached_at is not null or cached_shares='[]'::jsonb));
update public.sli_file_audit_smb_catalog
    set cached_shares=shares,cached_at=expires_at-interval '5 minutes' where result_status='ready';
grant select(cached_shares,cached_at),update(cached_shares,cached_at)
    on public.sli_file_audit_smb_catalog to adlog_user;

create function public.clear_file_audit_catalog_cache457()
returns trigger language plpgsql set search_path=pg_catalog,pg_temp as $$
begin
    new.cached_shares:='[]'::jsonb;
    new.cached_at:=null;
    return new;
end $$;
revoke all on function public.clear_file_audit_catalog_cache457() from public;
create trigger file_audit_catalog_cache_source457 before update of source_id on public.sli_file_audit_smb_catalog
    for each row when (old.source_id is distinct from new.source_id)
    execute function public.clear_file_audit_catalog_cache457();

-- Keep the legacy single-share opt-in and admit a server-created scope set only
-- when the current command, assignment and revision describe exactly that set.
alter function public.file_permissions_allowed405(uuid,text,text,boolean)
    rename to file_permissions_single457;
create function public.file_permissions_allowed405(p_agent uuid,p_revision text,p_scope text,p_verified boolean)
returns boolean language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select public.file_permissions_single457(p_agent,p_revision,p_scope,p_verified) or exists(
        select 1
        from public.sli_agents a
        cross join lateral jsonb_array_elements(a.assigned_modules) m
        cross join lateral (select a.file_audit->'request' as request) r
        cross join lateral (
            select coalesce(jsonb_agg(root order by n) filter (where not removed), '[]'::jsonb) as remaining,
                   coalesce(jsonb_agg(root->>'collection_scope_id' order by n), '[]'::jsonb) as all_scopes,
                   coalesce(jsonb_agg(root->>'collection_scope_id' order by n) filter (where removed), '[]'::jsonb) as restored,
                   bool_and(coalesce(a.file_audit#>>array['permissions_retained',root->>'collection_scope_id','state']='verified',false))
                       filter (where not removed) as retained_verified
            from jsonb_array_elements(r.request#>'{config,roots}') with ordinality items(root,n)
            cross join lateral (select coalesce((a.file_audit->'permissions_restore_scopes') ? (root->>'collection_scope_id'),false) as removed) s
        ) roots
        where a.id=p_agent and a.status='active' and p_verified is not null
          and a.collection_policy->'manage_windows_audit'='true'::jsonb
          and m->>'module_id'='sli.file-audit' and m->'enabled'='true'::jsonb
          and (select count(*) from jsonb_array_elements(a.assigned_modules) x where x->>'module_id'='sli.file-audit')=1
          and coalesce(m#>>'{config,source_kind}','server')='server'
          and m#>>'{config,policy_revision}'=r.request#>>'{command,policy_revision}'
          and (p_revision is null or p_revision=m#>>'{config,policy_revision}')
          and (p_scope is null or exists(select 1 from jsonb_array_elements(m#>'{config,roots}') scope
              where scope->>'collection_scope_id'=p_scope))
          and (not p_verified or a.file_audit->>'state'='verified')
          and (
            (r.request#>>'{command,action}'='apply'
              and m->'config'=r.request->'config'
              and roots.all_scopes=a.file_audit->'permissions_scopes'
              and roots.all_scopes=r.request#>'{command,collection_scope_ids}')
            or
            (r.request#>>'{command,action}'='restore'
              and m->'config'=jsonb_set(r.request->'config','{roots}',roots.remaining)
              and roots.retained_verified
              and jsonb_array_length(roots.remaining)>0
              and roots.restored=a.file_audit->'permissions_restore_scopes'
              and roots.restored=r.request#>'{command,collection_scope_ids}')
          )
    )
$$;
revoke all on function public.file_permissions_allowed405(uuid,text,text,boolean) from public;
grant execute on function public.file_permissions_allowed405(uuid,text,text,boolean) to adlog_user;

insert into public.schema_migrations(version,name) values(457,'file_audit_catalog_cache');
reset role;
commit;
