begin;
select pg_advisory_xact_lock(hashtext('sli_security_time_precision381'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=381 and name='security_time_precision')
       or exists(select 1 from public.schema_migrations where version>381) then
        raise exception 'security_time_precision381_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

do $patch381$ declare definition text; patched text; begin
    select pg_get_functiondef('public.attest_short_event337()'::regprocedure) into strict definition;
    patched:=replace(definition,
        $new$case when left(clock.parts[3],1) in ('6','7','8','9')
              or left(clock.parts[3],1)='5' and (substr(clock.parts[3],2) ~ '[1-9]'
                  or clock.parts[2]::integer%2=1) then 1 else 0 end$new$,
        $old$case when clock.parts[3]::integer>5
              or clock.parts[3]='5' and clock.parts[2]::integer%2=1 then 1 else 0 end$old$);
    if patched=definition then raise exception 'security_time_precision381_rollback_rounding_shape' using errcode='55000'; end if;
    definition:=patched;
    patched:=replace(definition,
        $new$\.([0-9]{6})([0-9]+)(Z|[+-][0-9]{2}:[0-9]{2})$new$,
        $old$\.([0-9]{6})([0-9])(Z|[+-][0-9]{2}:[0-9]{2})$old$);
    if patched=definition then raise exception 'security_time_precision381_rollback_clock_shape' using errcode='55000'; end if;
    execute patched;
end $patch381$;

-- Never undo a completed import. Restore unfinished retries byte-for-byte;
-- keep the audit and its accepted action after rollback, as in 379.
insert into public.sli_agent_packet_quarantine
select (jsonb_populate_record(null::public.sli_agent_packet_quarantine,a.details->'quarantine')).*
from public.sli_agent_audit a join public.sli_agent_packet_inbox i on i.packet_id::text=a.target
where a.action='packet_attestation_retry381' and i.imported_at is null
order by a.id desc
on conflict(packet_id) do nothing;

delete from public.schema_migrations where version=381 and name='security_time_precision';
reset role;
commit;
