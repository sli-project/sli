begin;
select pg_advisory_xact_lock(hashtext('sli_security_packet_attestation379'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=376 and name='workstation_import_isolation')
       or exists(select 1 from public.schema_migrations where version>=379) then
        raise exception 'security_packet_attestation379_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- Windows supplies 100 ns timestamps. The importer rounds decimal microseconds
-- HALF_EVEN; PostgreSQL's floating-point timestamp input can round a midpoint
-- differently (e.g. .0001255Z). Round the seven native digits as integers.
-- Both the native timestamp and the allocation bind new.time_created_utc;
-- XML, receipt, stream, ordinal, channel and provider admission remain intact.
do $patch379$ declare definition text; patched text; begin
    select pg_get_functiondef('public.attest_short_event337()'::regprocedure) into strict definition;
    patched:=replace(definition,
        $old$cross join public.semantic_default_installation installation$old$,
        $new$cross join lateral (select regexp_match(native.doc->>'time_created',
        '^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})\.([0-9]{6})([0-9])(Z|[+-][0-9]{2}:[0-9]{2})$') as parts) clock
    cross join public.semantic_default_installation installation$new$);
    if patched=definition then raise exception 'security_packet_attestation379_clock_shape' using errcode='55000'; end if;
    definition:=patched;
    patched:=replace(definition,
        $old$and (native.doc->>'time_created')::timestamptz=new.time_created_utc$old$,
        $new$and native.doc->>'time_created'=rep.representation->>'time_created'
      and (case when clock.parts is not null then
          (clock.parts[1]||clock.parts[4])::timestamptz
          + (clock.parts[2]::integer + case when clock.parts[3]::integer>5
              or clock.parts[3]='5' and clock.parts[2]::integer%2=1 then 1 else 0 end)*interval '1 microsecond'
          else (native.doc->>'time_created')::timestamptz end)=new.time_created_utc$new$);
    if patched=definition then raise exception 'security_packet_attestation379_shape' using errcode='55000'; end if;
    execute patched;
end $patch379$;

-- A single automatic retry through the ordinary inbox consumer, with all
-- admission checks. Preserve the entire refusal in the existing agent audit;
-- only the queue's quarantine marker moves. Payloads and receipts stay intact.
lock table public.sli_agent_audit in access exclusive mode;
do $$ declare prior text; no_inherit boolean; note text; begin
    select pg_get_expr(conbin,conrelid),connoinherit,obj_description(oid,'pg_constraint') into strict prior,no_inherit,note from pg_constraint
        where conrelid='public.sli_agent_audit'::regclass and conname='sli_agent_audit_action_check';
    alter table public.sli_agent_audit drop constraint sli_agent_audit_action_check;
    execute format('alter table public.sli_agent_audit add constraint sli_agent_audit_action_check check ((%s) or action=''packet_attestation_retry379'')%s',
        prior,case when no_inherit then ' no inherit' else '' end);
    execute format('comment on constraint sli_agent_audit_action_check on public.sli_agent_audit is %L',note);
end $$;
with retry as (
    delete from public.sli_agent_packet_quarantine q using public.sli_agent_packet_inbox i
    where q.packet_id=i.packet_id and q.reason_code='short_event_attestation_failed'
      and i.imported_at is null and i.module_disabled_at is null
      and i.envelope->>'module_id' in ('sli.windows.ad-dc','sli.windows.ad-dc-history')
      and i.collection_channel='Security'
    returning q.*
)
insert into public.sli_agent_audit(action,actor,target,details)
    select 'packet_attestation_retry379','migration379',packet_id::text,
        jsonb_build_object('quarantine',to_jsonb(retry)) from retry;

insert into public.schema_migrations(version,name) values(379,'security_packet_attestation');
reset role;
commit;
