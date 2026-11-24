begin;
select pg_advisory_xact_lock(hashtext('sli_file_permissions_opt_in405'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=404 and name='password_live_recovery')
       or exists(select 1 from public.schema_migrations where version>=405) then
        raise exception 'file_permissions_opt_in405_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- A previous assignment, even one marked enabled, carries no opt-in. Only the
-- matching current command and assignment can remain eligible while applying.
create function public.file_permissions_allowed405(p_agent uuid,p_revision text,p_scope text,p_verified boolean)
returns boolean language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select exists(
        select 1 from public.sli_agents a
        cross join lateral jsonb_array_elements(a.assigned_modules) m
        where a.id=p_agent and a.status='active' and p_verified is not null
          and a.collection_policy->'manage_windows_audit'='true'::jsonb
          and m->>'module_id'='sli.file-audit' and m->'enabled'='true'::jsonb
          and (select count(*) from jsonb_array_elements(a.assigned_modules) x
               where x->>'module_id'='sli.file-audit')=1
          and a.file_audit#>>'{request,command,action}'='apply'
          and m->'config'=a.file_audit#>'{request,config}'
          and coalesce(m#>>'{config,source_kind}','server')='server'
          and m#>>'{config,policy_revision}'=a.file_audit#>>'{request,command,policy_revision}'
          and (p_revision is null or p_revision=m#>>'{config,policy_revision}')
          and a.file_audit->>'permissions_scope'=m#>>'{config,roots,0,collection_scope_id}'
          and m#>'{config,roots,1}' is null
          and a.file_audit#>'{request,command,collection_scope_ids}'=jsonb_build_array(a.file_audit->>'permissions_scope')
          and (p_scope is null or p_scope=a.file_audit->>'permissions_scope')
          and (not p_verified or a.file_audit->>'state'='verified')
    )
$$;
revoke all on function public.file_permissions_allowed405(uuid,text,text,boolean) from public;
grant execute on function public.file_permissions_allowed405(uuid,text,text,boolean) to adlog_user;

create table public.file_permissions_restore405(signature regprocedure primary key,definition text not null,installed_definition text);
revoke all on public.file_permissions_restore405 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;

do $$ declare rec record; patched text; original_gate text; packet_read text; begin
    insert into public.file_permissions_restore405(signature,definition)
    select oid,pg_get_functiondef(oid) from pg_proc where oid=any(array[
        'public.file_action_row389(uuid,integer)'::regprocedure,
        'public.write_file_actions389(uuid,jsonb)'::regprocedure]);
    for rec in select * from public.file_permissions_restore405 loop
        original_gate:=$gate$    if not public.agent_module_enabled_v380('sli.file-audit') then
        raise exception 'module_disabled' using errcode='55000';
    end if;
$gate$;
        if rec.signature='public.write_file_actions389(uuid,jsonb)'::regprocedure then
            original_gate:=$gate$    if not public.agent_module_enabled_v380('sli.file-audit') then raise exception 'module_disabled' using errcode='55000'; end if;
$gate$;
            packet_read:='    select * into strict i from public.sli_agent_packet_inbox where packet_id=p_packet for update;';
        else
            packet_read:='    select * into strict i from public.sli_agent_packet_inbox where packet_id=p_packet;';
        end if;
        if strpos(rec.definition,original_gate)=0 or strpos(rec.definition,packet_read)=0 then
            raise exception 'file_permissions_opt_in405_writer_shape' using errcode='55000';
        end if;
        patched:=replace(replace(rec.definition,original_gate,''),packet_read,packet_read||
            case when rec.signature='public.write_file_actions389(uuid,jsonb)'::regprocedure then $lock$
    perform 1 from public.sli_agents where id=(i.envelope->>'agent_id')::uuid for update;$lock$ else '' end||$permit$
    if not public.file_permissions_allowed405((i.envelope->>'agent_id')::uuid,i.envelope->>'policy_revision',null,true) then
        raise exception 'module_disabled' using errcode='55000';
    end if;$permit$);
        if rec.signature='public.file_action_row389(uuid,integer)'::regprocedure then
            if strpos(patched,$check$    kind:=(doc->>'event_id')::integer; operation:=doc->>'operation';$check$)=0 then
                raise exception 'file_permissions_opt_in405_row_shape' using errcode='55000';
            end if;
            patched:=replace(patched,$check$    kind:=(doc->>'event_id')::integer; operation:=doc->>'operation';$check$,
                $restrict$    kind:=(doc->>'event_id')::integer; operation:=doc->>'operation';
    if kind<>4670 or operation<>'permissions' or not public.file_permissions_allowed405(a.id,
        i.envelope->>'policy_revision',doc->>'collection_scope_id',true) then
        raise exception 'file_action_kind_invalid' using errcode='22023';
    end if;$restrict$);
        end if;
        execute patched;
        update public.file_permissions_restore405 set installed_definition=pg_get_functiondef(rec.signature) where signature=rec.signature;
    end loop;
end $$;
insert into public.schema_migrations(version,name) values(405,'file_permissions_opt_in');
reset role;
commit;
