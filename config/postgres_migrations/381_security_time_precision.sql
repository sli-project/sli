begin;
select pg_advisory_xact_lock(hashtext('sli_security_time_precision381'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=379 and name='security_packet_attestation')
       or not exists(select 1 from public.schema_migrations where version=380 and name='disabled_module_intake')
       or exists(select 1 from public.schema_migrations where version>=381) then
        raise exception 'security_time_precision381_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- Retain every admission binding from 379. Compare the complete decimal tail:
-- 6..9 rounds up, 5 followed by any nonzero digit rounds up, exactly 50..0
-- rounds to an even microsecond. No floating-point input or time tolerance.
do $patch381$ declare definition text; patched text; begin
    select pg_get_functiondef('public.attest_short_event337()'::regprocedure) into strict definition;
    patched:=replace(definition,
        $old$\.([0-9]{6})([0-9])(Z|[+-][0-9]{2}:[0-9]{2})$old$,
        $new$\.([0-9]{6})([0-9]+)(Z|[+-][0-9]{2}:[0-9]{2})$new$);
    if patched=definition then raise exception 'security_time_precision381_clock_shape' using errcode='55000'; end if;
    definition:=patched;
    patched:=replace(definition,
        $old$case when clock.parts[3]::integer>5
              or clock.parts[3]='5' and clock.parts[2]::integer%2=1 then 1 else 0 end$old$,
        $new$case when left(clock.parts[3],1) in ('6','7','8','9')
              or left(clock.parts[3],1)='5' and (substr(clock.parts[3],2) ~ '[1-9]'
                  or clock.parts[2]::integer%2=1) then 1 else 0 end$new$);
    if patched=definition then raise exception 'security_time_precision381_rounding_shape' using errcode='55000'; end if;
    execute patched;
end $patch381$;

-- Retry only unimported AD/DC packets in the three affected channels through
-- the ordinary consumer. Preserve the complete refusal in the agent audit.
lock table public.sli_agent_audit in access exclusive mode;
do $$ declare prior text; no_inherit boolean; note text; begin
    select pg_get_expr(conbin,conrelid),connoinherit,obj_description(oid,'pg_constraint') into strict prior,no_inherit,note from pg_constraint
        where conrelid='public.sli_agent_audit'::regclass and conname='sli_agent_audit_action_check';
    alter table public.sli_agent_audit drop constraint sli_agent_audit_action_check;
    execute format('alter table public.sli_agent_audit add constraint sli_agent_audit_action_check check ((%s) or action=''packet_attestation_retry381'')%s',
        prior,case when no_inherit then ' no inherit' else '' end);
    execute format('comment on constraint sli_agent_audit_action_check on public.sli_agent_audit is %L',note);
end $$;
with retry as (
    delete from public.sli_agent_packet_quarantine q using public.sli_agent_packet_inbox i
    where q.packet_id=i.packet_id and q.reason_code='short_event_attestation_failed'
      and i.imported_at is null and i.module_disabled_at is null
      and i.envelope->>'module_id' in ('sli.windows.ad-dc','sli.windows.ad-dc-history')
      and i.collection_channel in ('Security','System','Directory Service')
    returning q.*
)
insert into public.sli_agent_audit(action,actor,target,details)
    select 'packet_attestation_retry381','migration381',packet_id::text,
        jsonb_build_object('quarantine',to_jsonb(retry)) from retry;

insert into public.schema_migrations(version,name) values(381,'security_time_precision');
reset role;
commit;
