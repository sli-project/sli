begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_password_checkpoint_proof403'));

do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=411 and name='password_successor_coverage')
       or exists(select 1 from public.schema_migrations where version>411) then
        raise exception 'password_successor_coverage411_rollback_preflight' using errcode='55000';
    end if;
end $$;

set local role adlog_storage_owner;

-- Existing successor rows retain any coverage proved and committed before rollback.
do $patch$
declare
    tracker constant regprocedure :=
        'public.track_password_frozen_entity_v2(jsonb,jsonb,bigint,bigint,text,jsonb,bigint,timestamptz,timestamptz)'::regprocedure;
    previous_fragment constant text := $from$successor_epoch=track_password_frozen_entity_v2.coverage_epoch,tracking_through=finalized_through
        where q.scope_digest=l.scope_digest and q.pin=l.pin and q.episode_key=l.episode_key;$from$;
    next_fragment constant text := $to$successor_epoch=track_password_frozen_entity_v2.coverage_epoch where q.scope_digest=l.scope_digest and q.pin=l.pin and q.episode_key=l.episode_key;$to$;
    definition text;
    previous_acl aclitem[];
    fragment_start integer;
begin
    select pg_get_functiondef(oid),proacl into definition,previous_acl
    from pg_proc where oid=tracker and proowner='adlog_storage_owner'::regrole
        and prosecdef and provolatile='v' and proconfig=array['search_path=pg_catalog, pg_temp'];
    fragment_start:=coalesce(strpos(definition,previous_fragment),0);
    if fragment_start=0
       or strpos(substr(definition,fragment_start+length(previous_fragment)),previous_fragment)>0 then
        raise exception 'password_successor_coverage411_shape' using errcode='55000';
    end if;

    definition:=replace(definition,previous_fragment,next_fragment);
    execute definition;
    if pg_get_functiondef(tracker) is distinct from definition
       or not exists(select 1 from pg_proc where oid=tracker and proacl is not distinct from previous_acl) then
        raise exception 'password_successor_coverage411_metadata' using errcode='55000';
    end if;
end $patch$;

reset role;
delete from public.schema_migrations where version=411 and name='password_successor_coverage';
commit;
