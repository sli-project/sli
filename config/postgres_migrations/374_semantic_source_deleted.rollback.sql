begin;
select pg_advisory_xact_lock(hashtext('sli_semantic_source_deleted374'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=374 and name='semantic_source_deleted')
       or exists(select 1 from public.schema_migrations where version>374) then
        raise exception 'semantic_source_deleted374_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
drop function public.semantic_source_exists374(bigint);
-- Keep jobs and receipts. Restore the original fingerprint so the previous
-- release still recognizes the terminal closed receipt after rollback.
update public.semantic_processing_outbox job set status='quarantined',completed_at=null,
    updated_at=coalesce((select (audit.details->>'original_updated_at')::timestamptz
        from public.semantic_control_audit audit
        where audit.action='semantic_quarantine_resolution' and audit.target=job.job_id::text
          and audit.details->>'outcome'='closed' and audit.details->>'reason'='source_deleted'
        order by audit.occurred_at desc limit 1),job.updated_at)
    where job.status='closed';
alter table public.semantic_processing_outbox drop constraint semantic_processing_outbox_status_check;
alter table public.semantic_processing_outbox add constraint semantic_processing_outbox_status_check
    check(status in ('queued','leased','completed','failed','quarantined'));
alter table public.semantic_processing_outbox drop constraint semantic_processing_outbox_terminal;
alter table public.semantic_processing_outbox add constraint semantic_processing_outbox_terminal check(
    (status='completed' and completed_at is not null and last_error_code is null)
    or (status in ('failed','quarantined') and last_error_code is not null)
    or status in ('queued','leased'));
delete from public.schema_migrations where version=374;
reset role;
commit;
