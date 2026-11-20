-- U01: finding-scoped risk decisions reuse the immutable suppression/audit model.
begin;
select pg_advisory_xact_lock(hashtext('ad_log_finding_risk_acceptance_v162'));
do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 162 requires membership in adlog_storage_owner';
    end if;
    if not exists(select 1 from schema_migrations where version=161 and name='ad_dc_agent')
       or exists(select 1 from schema_migrations where version>161) then
        raise exception 'migration 162 requires exact migration 161 ad_dc_agent';
    end if;
    if exists(select 1 from schema_migrations where version=162) then
        raise exception 'migration 162 already applied';
    end if;
end $$;

grant references on findings,auth_users to adlog_storage_owner;
grant select(id,status,repeat_count) on findings to adlog_storage_owner;
grant update(status,closed_at,updated_at) on findings to adlog_storage_owner;
grant insert on finding_status_history to adlog_storage_owner;
grant usage,select on sequence finding_status_history_id_seq to adlog_storage_owner;
set local role adlog_storage_owner;

alter table semantic_suppressions
    add column kind text not null default 'suppression' check (kind in ('suppression','risk_acceptance')),
    add column finding_id bigint references findings(id) on delete restrict,
    add column responsible_user_id bigint references auth_users(id) on delete restrict,
    alter column domain_id drop not null,
    drop constraint semantic_suppressions_scope_kind_check,
    drop constraint semantic_suppressions_check1;

alter table semantic_suppressions add constraint semantic_suppressions_scope_v162 check (
    (kind='suppression' and domain_id is not null and finding_id is null and responsible_user_id is null
        and ((scope_kind='subject_sid' and length(scope_value)<=184 and scope_value ~ '^S-1-([0-9]+-)+[0-9]+$')
            or (scope_kind='bucket' and scope_value in
                ('machine_account','system_account','known_gpo_refresh','interactive_admin','unknown'))))
    or (kind='risk_acceptance' and domain_id is null and scope_kind='finding'
        and finding_id is not null and scope_value=finding_id::text and responsible_user_id is not null)
);
create unique index semantic_suppressions_one_active_risk on semantic_suppressions(finding_id)
    where kind='risk_acceptance' and state='active';
create index semantic_suppressions_finding_history on semantic_suppressions(finding_id,id desc)
    where kind='risk_acceptance';
create index semantic_control_audit_finding_risk on semantic_control_audit
    ((details->'rule'->>'finding_id'),id desc) where details->'rule'->>'kind'='risk_acceptance';

-- The existing audit trigger snapshots all added fields and remains immutable.
-- The worker's bounded expire_semantic_suppressions_v160() also invokes this.
create function finding_risk_return_v162() returns trigger
language plpgsql security definer set search_path=pg_catalog,public as $$
declare previous_status text; next_status text;
begin
    if new.kind='risk_acceptance' and old.state='active' and new.state in ('expired','revoked') then
        select status,case when coalesce(repeat_count,0)>0 then 'repeated' else 'new' end
            into previous_status,next_status from public.findings where id=new.finding_id for update;
        update public.findings set status=next_status,closed_at=null,updated_at=clock_timestamp()
            where id=new.finding_id;
        insert into public.finding_status_history(finding_id,old_status,new_status,changed_by,note)
            values(new.finding_id,previous_status,next_status,new.changed_by,'risk_acceptance_' || new.state);
    end if;
    return new;
end $$;
create trigger finding_risk_return after update on semantic_suppressions
    for each row execute function finding_risk_return_v162();
revoke all on function finding_risk_return_v162() from public;

insert into schema_migrations(version,name) values(162,'finding_risk_acceptance');
commit;
