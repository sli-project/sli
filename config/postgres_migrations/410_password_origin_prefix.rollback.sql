begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_password_checkpoint_proof403'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=410 and name='password_origin_prefix')
       or exists(select 1 from public.schema_migrations where version>410) then
        raise exception 'password_origin_prefix410_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
lock table public.semantic_password_checkpoints,public.semantic_password_episode_budgets,public.password_origin_prefix410 in share mode nowait;

do $$ declare saved record; begin
    if exists(select 1 from public.password_origin_prefix410) or exists(
        select 1 from public.semantic_password_checkpoints c
        cross join lateral public.password_state_episodes385(c.state_document-'closed_admissions') a(e)
        where c.execution_json->>'rule_id'='qw.password-brute-force' and a.e->>'sequence'='0'
          and a.e->'frozen'='false'::jsonb and a.e->'prequalification'->0 is distinct from a.e->'seed'
    ) then raise exception 'password_origin_prefix410_rollback_pending_state' using errcode='55000'; end if;
    if (select count(*) from public.password_origin_restore410)<>4 then
        raise exception 'password_origin_prefix410_rollback_metadata' using errcode='55000';
    end if;
    for saved in select * from public.password_origin_restore410 loop
        if not exists(select 1 from pg_proc p where p.oid=saved.signature and p.proowner=saved.owner_oid
            and p.proacl is not distinct from saved.acl and pg_get_functiondef(p.oid)=saved.installed_definition) then
            raise exception 'password_origin_prefix410_rollback_metadata' using errcode='55000';
        end if;
        execute saved.definition;
    end loop;
end $$;

drop function public.password_sync_origin_prefix410(public.semantic_password_checkpoints,jsonb,text,timestamptz,bigint,text[]);
drop function public.password_verify_origins410(public.semantic_password_checkpoints,jsonb,text[]);
drop function public.password_check_origin_admission410(public.semantic_password_checkpoints,jsonb);
drop function public.password_check_origin_extension410(jsonb,jsonb,timestamptz);
drop function public.read_password_origin_prefix410(jsonb,jsonb,bigint,bigint,text,integer);
drop function public.read_password_checkpoint410(jsonb,jsonb);
drop function public.password_assert_origin_prefix410(public.semantic_password_checkpoints);
drop table public.password_origin_prefix410,public.password_origin_restore410;
reset role;
delete from public.schema_migrations where version=410 and name='password_origin_prefix';
commit;
