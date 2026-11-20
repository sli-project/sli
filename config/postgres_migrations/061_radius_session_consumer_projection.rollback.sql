-- Roll back only before any session delivery has been consumed.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_radius_session_consumer_v61')
);

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=61 and name='radius_session_consumer_projection'
    ) then
        raise exception 'migration 061 is not applied';
    end if;
    if exists (select 1 from radius_session_projection_receipts)
       or exists (select 1 from radius_vpn_session_projection) then
        raise exception 'migration 061 rollback forbidden after consumer output';
    end if;
    if exists (
        select 1 from acquisition_delivery_outbox
        where delivery_state in ('leased','failed','delivered')
    ) then
        raise exception 'migration 061 rollback forbidden with processed delivery state';
    end if;
end
$$;

set local role adlog_storage_owner;

drop index if exists radius_vpn_session_projection_state_idx;
drop index if exists radius_vpn_session_projection_principal_idx;
drop table radius_vpn_session_projection;
drop table radius_session_projection_receipts;

drop index acquisition_delivery_outbox_claim_idx;
alter table acquisition_delivery_outbox
    drop constraint acquisition_delivery_outbox_error_code_check,
    drop constraint acquisition_delivery_outbox_lease_check,
    drop constraint acquisition_delivery_outbox_delivery_state_check;
alter table acquisition_delivery_outbox
    add constraint acquisition_delivery_outbox_delivery_state_check
        check (
            delivery_state in ('queued','delivered','quarantined')
        );
create index acquisition_delivery_outbox_claim_idx
    on acquisition_delivery_outbox(
        delivery_state,created_at,delivery_id
    );
alter table acquisition_delivery_outbox
    drop column updated_at,
    drop column last_error_code,
    drop column heartbeat_at,
    drop column lease_until,
    drop column lease_token,
    drop column available_at,
    drop column attempt_count;

delete from schema_migrations
where version=61 and name='radius_session_consumer_projection';

reset role;

revoke update(
    delivery_state,delivered_at
) on acquisition_delivery_outbox
from adlog_radius_session_consumer;
revoke select on table
    acquisition_delivery_outbox,
    radius_accounting_session_observations
from adlog_radius_session_consumer;
revoke usage on schema public from adlog_radius_session_consumer;
revoke adlog_radius_session_consumer from adlog_storage_owner;
drop role adlog_radius_session_consumer;

commit;
