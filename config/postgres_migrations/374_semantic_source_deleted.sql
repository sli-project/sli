begin;
select pg_advisory_xact_lock(hashtext('sli_semantic_source_deleted374'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=373 and name='dc_pipeline_capacity')
       or exists(select 1 from public.schema_migrations where version>=374) then
        raise exception 'semantic_source_deleted374_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
-- Existence only: an unattested or altered short row must not be mistaken for
-- deletion when it is absent from the admitted-source view.
create function public.semantic_source_exists374(p_id bigint) returns boolean
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select exists(select 1 from public.event_hot where event_id=p_id)
        or exists(select 1 from public.event_cold_facts where event_id=p_id)
$$;
revoke all on function public.semantic_source_exists374(bigint) from public;
grant execute on function public.semantic_source_exists374(bigint) to adlog_semantic_worker;
alter table public.semantic_processing_outbox drop constraint semantic_processing_outbox_status_check;
alter table public.semantic_processing_outbox add constraint semantic_processing_outbox_status_check
    check(status in ('queued','leased','completed','failed','quarantined','closed'));
alter table public.semantic_processing_outbox drop constraint semantic_processing_outbox_terminal;
alter table public.semantic_processing_outbox add constraint semantic_processing_outbox_terminal check(
    (status='completed' and completed_at is not null and last_error_code is null)
    or (status='closed' and completed_at is not null and last_error_code is not null)
    or (status in ('failed','quarantined') and last_error_code is not null)
    or status in ('queued','leased'));
insert into public.schema_migrations(version,name) values(374,'semantic_source_deleted');
reset role;
commit;
