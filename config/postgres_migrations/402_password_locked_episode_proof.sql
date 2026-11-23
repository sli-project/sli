begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_password_locked_episode_proof402'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=401 and name='dc_task_service_catalog')
       or exists(select 1 from public.schema_migrations where version>=402) then
        raise exception 'password_locked_episode_proof402_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

create function public.read_locked_password_episode402(s jsonb,execution jsonb,p_episode text)
returns table(ledger jsonb,portions jsonb)
language plpgsql volatile security definer set search_path=pg_catalog,pg_temp as $$
declare locked jsonb; identity jsonb;
begin
    -- The publication lock authorizes and validates the exact episode. The
    -- entity and ledger locks remain held while the same ordered chain is read.
    locked:=public.lock_password_publication_v2(s,execution,p_episode);
    identity:=public.password_v2_identity(s,execution);
    return query
    select locked,coalesce(jsonb_agg(jsonb_build_object(
        'signal_id',encode(sha256(convert_to(public.password_v2_json_compact(p.document-'received_at_utc'),'UTF8')),'hex'),
        'document_json',p.document) order by p.part_no),'[]'::jsonb)
    from jsonb_array_elements(public.password_v2_episode_documents(s,identity->>'pin',p_episode))
         with ordinality as p(document,part_no);
end $$;
revoke all on function public.read_locked_password_episode402(jsonb,jsonb,text)
    from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
grant execute on function public.read_locked_password_episode402(jsonb,jsonb,text) to adlog_semantic_worker;

reset role;
insert into public.schema_migrations(version,name) values(402,'password_locked_episode_proof');
commit;
