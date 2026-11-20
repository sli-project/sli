-- Explicit operator rollback only; never invoked by runtime.
begin;
select pg_advisory_xact_lock(hashtext('sli_sigma_rule_labels_v286'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=286 and name='sigma_rule_labels')
       or exists(select 1 from public.schema_migrations where version>286) then
        raise exception 'migration 286 rollback prerequisites failed';
    end if;
end $$;
set local role adlog_sigma_owner;
drop function sli_sigma.read_rule_labels(uuid,text,text,uuid,text);
reset role;
set local role adlog_storage_owner;
delete from public.schema_migrations where version=286 and name='sigma_rule_labels';
commit;
