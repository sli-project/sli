begin;
select pg_advisory_xact_lock(hashtext('sli_security_packet_attestation379'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=379 and name='security_packet_attestation')
       or exists(select 1 from public.schema_migrations where version>379) then
        raise exception 'security_packet_attestation379_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
do $patch379$ declare definition text; patched text; begin
    select pg_get_functiondef('public.attest_short_event337()'::regprocedure) into strict definition;
    patched:=replace(definition,
        $new$and native.doc->>'time_created'=rep.representation->>'time_created'
      and (case when clock.parts is not null then
          (clock.parts[1]||clock.parts[4])::timestamptz
          + (clock.parts[2]::integer + case when clock.parts[3]::integer>5
              or clock.parts[3]='5' and clock.parts[2]::integer%2=1 then 1 else 0 end)*interval '1 microsecond'
          else (native.doc->>'time_created')::timestamptz end)=new.time_created_utc$new$,
        $old$and (native.doc->>'time_created')::timestamptz=new.time_created_utc$old$);
    if patched=definition then raise exception 'security_packet_attestation379_rollback_shape' using errcode='55000'; end if;
    definition:=patched;
    patched:=replace(definition,
        $new$cross join lateral (select regexp_match(native.doc->>'time_created',
        '^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})\.([0-9]{6})([0-9])(Z|[+-][0-9]{2}:[0-9]{2})$') as parts) clock
    cross join public.semantic_default_installation installation$new$,
        $old$cross join public.semantic_default_installation installation$old$);
    if patched=definition then raise exception 'security_packet_attestation379_rollback_clock_shape' using errcode='55000'; end if;
    execute patched;
end $patch379$;
-- Keep audit rows and their accepted action, and never undo a completed import.
-- Unfinished retries return to quarantine with every original field preserved.
insert into public.sli_agent_packet_quarantine
select (jsonb_populate_record(null::public.sli_agent_packet_quarantine,a.details->'quarantine')).*
from public.sli_agent_audit a join public.sli_agent_packet_inbox i on i.packet_id::text=a.target
where a.action='packet_attestation_retry379' and i.imported_at is null
order by a.id desc
on conflict(packet_id) do nothing;
delete from public.schema_migrations where version=379 and name='security_packet_attestation';
reset role;
commit;
