begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_semantic_calibration_reviews_v33'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'rollback 033 requires membership in adlog_storage_owner';
    end if;
    if exists (select 1 from semantic_scenario_reviews) then
        raise exception 'rollback 033 refused: semantic scenario reviews exist';
    end if;
end
$$;

set local role adlog_storage_owner;

drop trigger if exists trg_semantic_scenario_review_immutability
    on semantic_scenario_reviews;
drop function if exists enforce_semantic_scenario_review_immutability();
drop table if exists semantic_scenario_reviews;
delete from schema_migrations where version=33 and name='semantic_calibration_reviews';

commit;
