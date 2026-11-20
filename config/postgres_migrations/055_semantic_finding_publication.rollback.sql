begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_semantic_findings_v55'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 055 rollback requires membership in adlog_storage_owner';
    end if;
    if exists(select 1 from semantic_finding_publications) then
        raise exception 'migration 055 rollback blocked: publication evidence exists';
    end if;
end
$$;

set local role adlog_storage_owner;

drop trigger if exists trg_semantic_finding_publication_immutability
    on semantic_finding_publications;
drop table if exists semantic_finding_publications;
drop function if exists enforce_semantic_finding_publication_immutability();

delete from schema_migrations
where version=55 and name='semantic_finding_publication';

reset role;

revoke select,insert,update on table findings from adlog_semantic_worker;
revoke select,insert on table
    finding_evidence,
    finding_entities,
    finding_status_history
from adlog_semantic_worker;
revoke usage,select on sequence
    findings_id_seq,
    finding_evidence_id_seq,
    finding_entities_id_seq,
    finding_status_history_id_seq
from adlog_semantic_worker;
revoke references on table findings from adlog_storage_owner;

commit;
