begin;
select pg_advisory_xact_lock(hashtext('sli_password_commit_cost384'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=383 and name='detection_source_lock')
       or exists(select 1 from public.schema_migrations where version>=384) then
        raise exception 'password_commit_cost384_preflight' using errcode='55000'; end if;
end $$;
set local role adlog_storage_owner;
create table public.password_commit_restore384(kind text not null,signature text not null,definition text not null,
    installed_definition text,owner_oid oid,acl aclitem[],primary key(kind,signature));
revoke all on public.password_commit_restore384 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
insert into public.password_commit_restore384(kind,signature,definition,owner_oid,acl)
select 'function',oid::regprocedure::text,pg_get_functiondef(oid),proowner,proacl from pg_proc where oid=any(array[
    'public.password_v2_assert_episode(public.semantic_password_episode_budgets)'::regprocedure,
    'public.password_v2_deferred()'::regprocedure,
    'public.password_v2_assert_checkpoint(public.semantic_password_checkpoints)'::regprocedure,
    'public.password_schedule_state_check375()'::regprocedure,
    'public.password_v2_state_ledger_complete()'::regprocedure,
    'public.prepare_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text[])'::regprocedure,
    'public.read_password_event_window362(jsonb,jsonb)'::regprocedure,
    'public.password_event_clock362(jsonb,jsonb)'::regprocedure]);
insert into public.password_commit_restore384(kind,signature,definition)
select 'trigger',tgname,pg_get_triggerdef(oid) from pg_trigger where tgname in(
    'password_v2_ledger_complete','password_v2_qw_complete','password_v2_jobs_complete');
do $$ begin
    if exists(select 1 from public.password_commit_restore384 where kind='function'
        and owner_oid is distinct from 'adlog_storage_owner'::regrole) then
        raise exception 'password_commit_cost384_owner' using errcode='55000'; end if;
end $$;

-- An episode assertion also validates the shared checkpoint. Repeating its
-- full 3000-member structural/projection check for every entity is quadratic.
-- Cache only while a private state work row exists; every projection/state
-- mutation invalidates it, including writes after a constraint drain.
alter table public.password_state_checks375 add column checked_checkpoint jsonb;
do $$ declare body text; begin
    select definition into strict body from public.password_commit_restore384
        where kind='function' and signature='password_schedule_state_check375()';
    if strpos(body,'on conflict do nothing')=0 then
        raise exception 'password_commit_cost384_state_schedule_shape' using errcode='55000'; end if;
    execute replace(body,'on conflict do nothing','on conflict(scope_digest,pin) do update set checked_checkpoint=null');
    select definition into strict body from public.password_commit_restore384
        where kind='function' and signature='password_v2_assert_checkpoint(semantic_password_checkpoints)';
    body:=replace(body,E'\n STABLE\n',E'\n VOLATILE\n');
    if strpos(body,E'declare projected jsonb; expected_time timestamptz;\nbegin')=0 then
        raise exception 'password_commit_cost384_checkpoint_shape' using errcode='55000'; end if;
    body:=replace(body,E'declare projected jsonb; expected_time timestamptz;\nbegin',
        E'declare projected jsonb; expected_time timestamptz; checked jsonb;\nbegin\n    select q.checked_checkpoint into checked from public.password_state_checks375 q where q.scope_digest=c.scope_digest and q.pin=c.pin;\n    if checked=to_jsonb(c) then return; end if;');
    body:=replace(body,E'\nend $function$',E'\n    update public.password_state_checks375 q set checked_checkpoint=to_jsonb(c)\n        where q.scope_digest=c.scope_digest and q.pin=c.pin;\nend $function$');
    execute body;
    select definition into strict body from public.password_commit_restore384
        where kind='function' and signature='prepare_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text[])';
    if strpos(body,'    if entity_keys is null')=0 then
        raise exception 'password_commit_cost384_prepare_shape' using errcode='55000'; end if;
    -- Only the producer, already holding source/checkpoint locks, creates the
    -- shared state work row. Read-only proof/risk paths never contend for it.
    execute replace(body,'    if entity_keys is null',
        E'    insert into public.password_state_checks375(scope_digest,pin,checked_checkpoint) values(c.scope_digest,c.pin,to_jsonb(c)) on conflict do nothing;\n    if entity_keys is null');
    select definition into strict body from public.password_commit_restore384
        where kind='function' and signature='password_v2_state_ledger_complete()';
    if strpos(body,'delete from public.password_state_checks375 q where q.scope_digest=new.scope_digest and q.pin=new.pin;')=0 then
        raise exception 'password_commit_cost384_state_drain_shape' using errcode='55000'; end if;
    body:=replace(body,'delete from public.password_state_checks375 q where q.scope_digest=new.scope_digest and q.pin=new.pin;','');
    execute replace(body,'return null;',E'delete from public.password_state_checks375 q where q.scope_digest=new.scope_digest and q.pin=new.pin;\n    return null;');
end $$;

-- A private work set, never a caller flag. Deleted at constraint drain, or
-- rolled back. An INSERT after SET CONSTRAINTS re-arms the deferred validator.
-- The first OLD ledger is the previously committed, immutable prefix authority.
create table public.password_episode_checks384(
    scope_digest bytea not null,pin text not null,episode_key text not null,
    previous_ledger public.semantic_password_episode_budgets,
    checked_ledger jsonb,freeze_revision bigint,primary key(scope_digest,pin,episode_key));
revoke all on public.password_episode_checks384 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
create function public.password_schedule_episode384() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare k bytea; p text; e text; d jsonb; previous public.semantic_password_episode_budgets; freeze_before bigint;
begin
    if tg_table_name='semantic_password_episode_budgets' then
        k:=new.scope_digest; p:=new.pin; e:=new.episode_key;
        if tg_op='UPDATE' then
            previous:=old;
            if not old.frozen and new.frozen and new.last_sequence>0 then freeze_before:=old.admitted_revision; end if;
        end if;
    elsif tg_table_name='semantic_qw_signals' then
        d:=new.document_json;
    else
        select q.document_json into d from public.semantic_qw_signals q
            where q.signal_id=coalesce(new.qw_signal_id,old.qw_signal_id);
    end if;
    if tg_table_name<>'semantic_password_episode_budgets' then
        if not public.password_v2_managed(d) then return null; end if;
        k:=public.password_v2_scope_key(d#>'{evidence_refs,0,scope}');
        p:=d#>>'{password_context,pin}'; e:=d#>>'{password_context,episode_key}';
    end if;
    insert into public.password_episode_checks384 as q(scope_digest,pin,episode_key,previous_ledger,freeze_revision)
        values(k,p,e,previous,freeze_before) on conflict(scope_digest,pin,episode_key) do update
        set checked_ledger=null,freeze_revision=greatest(q.freeze_revision,excluded.freeze_revision);
    return null;
end $$;
revoke all on function public.password_schedule_episode384() from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;

create function public.password_invalidate_episode384() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    update public.password_episode_checks384 q set checked_ledger=null
        where q.scope_digest=new.scope_digest and q.pin=new.pin;
    return null;
end $$;
revoke all on function public.password_invalidate_episode384() from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
create trigger password_episode_checkpoint384 after update on public.semantic_password_checkpoints
    for each row execute function public.password_invalidate_episode384();

-- Keep every identity, ancestry, totals, checkpoint, successor and job check.
-- Only the committed immutable prefix can be reused. A changed old sequence
-- cannot hide behind the suffix: immutable portions plus its exact count fence
-- insertions into the prefix. With no trusted prefix, decode the entire chain.
do $$ declare body text; before_patch text; after_patch text; begin
    select definition into strict body from public.password_commit_restore384
        where kind='function' and signature='password_v2_assert_episode(semantic_password_episode_budgets)';
    body:=replace(body,E'\n STABLE SECURITY DEFINER',E'\n VOLATILE SECURITY DEFINER');
    before_patch:=$old$    successor public.semantic_password_episode_budgets%rowtype;
begin$old$;
    after_patch:=$new$    successor public.semantic_password_episode_budgets%rowtype;
    baseline public.semantic_password_episode_budgets; checked jsonb; prefix jsonb; work public.password_episode_checks384;
begin
    select q.* into work from public.password_episode_checks384 q
        where q.scope_digest=l.scope_digest and q.pin=l.pin and q.episode_key=l.episode_key;
    baseline:=work.previous_ledger; checked:=work.checked_ledger;
    if checked=to_jsonb(l) then return; end if;$new$;
    if strpos(body,before_patch)=0 then raise exception 'password_commit_cost384_assert_shape' using errcode='55000'; end if;
    body:=replace(body,before_patch,after_patch);
    before_patch:=$old$    docs:=public.password_v2_episode_documents(l.scope_json,l.pin,l.episode_key);
    for group_docs$old$;
    after_patch:=$new$    docs:=public.password_v2_episode_documents(l.scope_json,l.pin,l.episode_key);
    if baseline.last_sequence>0 and l.admission_xid=pg_current_xact_id()
       and baseline.admission_xid<>pg_current_xact_id()
       and baseline.last_sequence=l.admission_first_sequence-1 then
        select jsonb_agg(a.value order by (a.value#>>'{password_context,portion_index}')::integer) into prefix
            from jsonb_array_elements(docs) a(value)
            where (a.value#>>'{password_context,sequence}')::integer=baseline.last_sequence;
        previous:=public.password_v2_decode(l.scope_json,l.execution_json,prefix);
        if previous->>'emission_id' is distinct from baseline.last_emission_id
           or previous->'endpoint' is distinct from baseline.last_admitted_endpoint
           or previous->>'root_id' is distinct from baseline.root_id
           or (select count(*) from jsonb_array_elements(docs) a(value)
               where (a.value#>>'{password_context,sequence}')::integer<=baseline.last_sequence)<>baseline.reserved_portions then
            raise exception 'password_v2_ancestry_conflict' using errcode='55000'; end if;
        n:=baseline.last_sequence; refs:=baseline.reserved_ref_occurrences;
        portions:=baseline.reserved_portions; bytes:=baseline.reserved_xml_bytes; first_root:=baseline.root_id;
    end if;
    for group_docs$new$;
    if strpos(body,before_patch)=0 then raise exception 'password_commit_cost384_prefix_shape' using errcode='55000'; end if;
    body:=replace(body,before_patch,after_patch);
    before_patch:=$old$from jsonb_array_elements(docs) a(value) group by (a.value#>>'{password_context,sequence}')::integer$old$;
    after_patch:=$new$from jsonb_array_elements(docs) a(value) where (a.value#>>'{password_context,sequence}')::integer>n
        group by (a.value#>>'{password_context,sequence}')::integer$new$;
    if strpos(body,before_patch)=0 then raise exception 'password_commit_cost384_suffix_shape' using errcode='55000'; end if;
    body:=replace(body,before_patch,after_patch);
    body:=replace(body,E'\nEND;\n',E'\n    update public.password_episode_checks384 q set checked_ledger=to_jsonb(l)\n        where q.scope_digest=l.scope_digest and q.pin=l.pin and q.episode_key=l.episode_key;\nEND;\n');
    -- pg_get_functiondef preserves the original lower-case body.
    body:=replace(body,E'\nend $function$',E'\n    update public.password_episode_checks384 q set checked_ledger=to_jsonb(l)\n        where q.scope_digest=l.scope_digest and q.pin=l.pin and q.episode_key=l.episode_key;\nend $function$');
    execute body;
end $$;

create or replace function public.password_v2_deferred() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare l public.semantic_password_episode_budgets; c public.semantic_password_checkpoints; ep jsonb; freeze_before bigint;
begin
    select q.freeze_revision into freeze_before from public.password_episode_checks384 q
        where q.scope_digest=new.scope_digest and q.pin=new.pin and q.episode_key=new.episode_key;
    if not found then return null; end if;
    select q.* into l from public.semantic_password_episode_budgets q
        where q.scope_digest=new.scope_digest and q.pin=new.pin and q.episode_key=new.episode_key;
    if not found then raise exception 'password_v2_admission_incomplete' using errcode='55000'; end if;
    if freeze_before is not null then
        select q.* into c from public.semantic_password_checkpoints q where q.scope_digest=l.scope_digest and q.pin=l.pin;
        select a.value into ep from jsonb_array_elements(c.state_document->'episodes') a(value) where a.value->>'key'=l.episode_key;
        if ep is null or ep->'frozen' is distinct from 'true'::jsonb
            or ep->'budget' is distinct from public.password_v2_totals(l)
            or ep->>'root_id' is distinct from l.root_id or ep->>'last_emission' is distinct from l.last_emission_id
            or (ep->>'sequence')::integer<>l.last_sequence
            or c.last_observed_token<>c.active_token or c.state_revision<=freeze_before then
            raise exception 'password_v2_freeze_completion_incomplete' using errcode='55000'; end if;
    end if;
    perform public.password_v2_assert_episode(l);
    delete from public.password_episode_checks384 q
        where q.scope_digest=new.scope_digest and q.pin=new.pin and q.episode_key=new.episode_key;
    return null;
end $$;
drop trigger password_v2_ledger_complete on public.semantic_password_episode_budgets;
drop trigger password_v2_qw_complete on public.semantic_qw_signals;
drop trigger password_v2_jobs_complete on public.semantic_risk_evaluation_jobs;
create trigger password_v2_ledger_complete after insert or update on public.semantic_password_episode_budgets
    for each row execute function public.password_schedule_episode384();
create trigger password_v2_qw_complete after insert on public.semantic_qw_signals
    for each row execute function public.password_schedule_episode384();
create trigger password_v2_jobs_complete after insert or update or delete on public.semantic_risk_evaluation_jobs
    for each row execute function public.password_schedule_episode384();
create constraint trigger password_v2_episode_batch384 after insert on public.password_episode_checks384
    deferrable initially deferred for each row execute function public.password_v2_deferred();

-- Count the entire horizon before excluding the checkpoint's immutable native
-- identities. Late arrivals have new identities and are still read/classified.
-- The finalizer independently revalidates native commitments as before.
do $$ declare body text; before_patch text; after_patch text; begin
    select definition into strict body from public.password_commit_restore384 where kind='function'
        and signature='read_password_event_window362(jsonb,jsonb)';
    before_patch:=$old$) select array_agg(to_jsonb(c) order by c.time_created_utc,c.id),count(*)::integer
      into candidates,n from bounded_candidates c;$old$;
    after_patch:=$new$), missing as (
        select c.* from bounded_candidates c where not exists(
            select 1 from public.semantic_password_window_members m
            where m.scope_digest=public.password_v2_scope_key(s)
              and m.pin=public.password_v2_identity(s,execution)->>'pin' and m.native_id=c.id
              and m.member_document#>>'{witness,ref,sha256}'=c.normalized_sha256
              and public.password_v2_time(m.member_document#>'{witness,at}')=c.time_created_utc)
    ) select array_agg(to_jsonb(c) order by c.time_created_utc,c.id),
        case when (select count(*) from bounded_candidates)>10000 then 10001 else count(*)::integer end
      into candidates,n from missing c;$new$;
    if strpos(body,before_patch)=0 then raise exception 'password_commit_cost384_window_shape' using errcode='55000'; end if;
    execute replace(body,before_patch,after_patch);
end $$;

-- Local 383/384 comparison: 1495 decisions, 70 IPs, COMMIT 322.258s ->
-- 2.049s after episode coalescing (before checkpoint caching). Keep this
-- measured slice rather than expanding unqualified brute-force state toward
-- its 4MiB bound. The 600s continuity slice, whole timestamp groups, 10000
-- native rows and 32MiB native budget remain unchanged.
do $$ declare body text; begin
    select definition into strict body from public.password_commit_restore384 where kind='function'
        and signature='password_event_clock362(jsonb,jsonb)';
    if strpos(body,'decision_members integer:=299*(600/120)')=0 then
        raise exception 'password_commit_cost384_clock_shape' using errcode='55000'; end if;
    execute replace(body,'decision_members integer:=299*(600/120)','decision_members integer:=1495');
end $$;

update public.password_commit_restore384 d set installed_definition=pg_get_functiondef(d.signature::regprocedure) where kind='function';
update public.password_commit_restore384 d set installed_definition=pg_get_triggerdef(t.oid)
from pg_trigger t where d.kind='trigger' and d.signature=t.tgname;
do $$ begin
    if exists(select 1 from public.password_commit_restore384 d join pg_proc p on p.oid=d.signature::regprocedure
        where d.kind='function' and (p.proowner is distinct from d.owner_oid or p.proacl is distinct from d.acl)) then
        raise exception 'password_commit_cost384_metadata_changed' using errcode='55000'; end if;
end $$;
insert into public.schema_migrations(version,name) values(384,'password_commit_cost');
reset role;
commit;
