begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_password_checkpoint_proof403'));

do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=414 and name='file_audit_smb_catalog')
       or exists(select 1 from public.schema_migrations where version>=415) then
        raise exception 'password_portion_canonical415_preflight' using errcode='55000';
    end if;
end $$;

set local role adlog_storage_owner;

create table public.password_portion_canonical_restore415(
    signature regprocedure primary key, original_definition text not null,
    installed_definition text not null, owner_oid oid not null, acl aclitem[]);
revoke all on public.password_portion_canonical_restore415 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;

do $patch$
declare
    decoder constant regprocedure := 'public.password_v2_decode(jsonb,jsonb,jsonb)'::regprocedure;
    previous_declaration constant text := 'nid bigint; expected_id text;';
    next_declaration constant text := 'nid bigint; expected_id text; signed_document text;';
    previous_size constant text := $from$
           or octet_length(d::text)>524288 or octet_length(public.password_v2_json_compact(d))>524288 then
            raise exception 'password_v2_portion_invalid' using errcode='22023'; end if;
        perform public.password_v2_time(d->'received_at_utc');$from$;
    next_size constant text := $to$
           or octet_length(d::text)>524288 then
            raise exception 'password_v2_portion_invalid' using errcode='22023'; end if;
        signed_document:=public.password_v2_json_compact(d-'received_at_utc');
        -- The validated object has this required member and other members.
        -- Its key position cannot change the full canonical byte length.
        -- Canonicalize the timestamp at the original child depth.
        if octet_length(signed_document)+octet_length(',"received_at_utc":')
           +octet_length(public.password_v2_json_compact(d->'received_at_utc',1))>524288 then
            raise exception 'password_v2_portion_invalid' using errcode='22023'; end if;
        perform public.password_v2_time(d->'received_at_utc');$to$;
    previous_hash constant text := $from$convert_to(public.password_v2_json_compact(d-'received_at_utc'),'UTF8')$from$;
    next_hash constant text := 'convert_to(signed_document,''UTF8'')';
    original text; patched text; decoder_owner oid; decoder_acl aclitem[];
    fragment text; first_at integer;
begin
    select pg_get_functiondef(oid),proowner,proacl into strict original,decoder_owner,decoder_acl
    from pg_proc where oid=decoder and proowner='adlog_storage_owner'::regrole and prosecdef
      and provolatile='s' and proconfig=array['search_path=pg_catalog, pg_temp'];
    foreach fragment in array array[previous_declaration,previous_size,previous_hash] loop
        first_at:=strpos(original,fragment);
        if first_at=0 or strpos(substr(original,first_at+length(fragment)),fragment)>0 then
            raise exception 'password_portion_canonical415_shape' using errcode='55000';
        end if;
    end loop;

    patched:=replace(replace(replace(original,previous_declaration,next_declaration),
        previous_size,next_size),previous_hash,next_hash);
    execute patched;
    if pg_get_functiondef(decoder) is distinct from patched or not exists(
        select 1 from pg_proc where oid=decoder and proowner=decoder_owner and proacl is not distinct from decoder_acl
    ) then raise exception 'password_portion_canonical415_metadata' using errcode='55000'; end if;

    insert into public.password_portion_canonical_restore415
        values(decoder,original,patched,decoder_owner,decoder_acl);
end $patch$;

reset role;
insert into public.schema_migrations(version,name) values(415,'password_portion_canonical');
commit;
