begin;
select pg_advisory_xact_lock(hashtext('sli_file_audit_check_receipt_retention431'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=424 and name='home_read_indexes')
       or exists(select 1 from public.schema_migrations where version>=431) then
        raise exception 'file_audit_check_receipt_retention431_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- Mark the historical rows without deleting data during schema installation.
alter table sli_plugin_file_audit.audit_receipts add column legacy_check_receipt boolean not null default true;
alter table sli_plugin_file_audit.audit_receipts alter column legacy_check_receipt set default false;

create function public.prune_file_audit_check_receipts431(p_limit integer) returns bigint
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare
    v_deleted bigint;
begin
    if p_limit is null or p_limit not between 1 and 1000 then
        raise exception 'file_audit_check_receipt_retention431_invalid_limit' using errcode='22023';
    end if;
    with ranked as (
        select r.receipt_id, row_number() over history as position,
            count(*) over (history rows between unbounded preceding and unbounded following) as total
        from sli_plugin_file_audit.audit_receipts r
        where r.legacy_check_receipt and r.action='check' and r.state='failed'
          and r.observed_at is not null
        window history as (
            partition by r.command_id,r.collection_scope_id,r.state,r.reason_code,r.required_masks,r.actual_masks
            order by r.observed_at,r.receipt_id
        )
    ), candidates as (
        select receipt_id from ranked where position>1 and position<total order by receipt_id limit p_limit
    )
    delete from sli_plugin_file_audit.audit_receipts r using candidates c where r.receipt_id=c.receipt_id;
    get diagnostics v_deleted = row_count;
    return v_deleted;
end $$;
revoke all on function public.prune_file_audit_check_receipts431(integer) from public;
grant execute on function public.prune_file_audit_check_receipts431(integer) to adlog_storage_lifecycle_delete;

insert into public.schema_migrations(version,name) values(431,'file_audit_check_receipt_retention');
commit;
