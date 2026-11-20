begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_ad_context_shared_entity_identity_v45'));

do $$
declare
    v2_only_rows bigint;
begin
    select count(*) into v2_only_rows
    from entities_v2 v2
    left join observed_entities v1 on v1.id=v2.id
    where v1.id is null;

    if v2_only_rows <> 0 then
        raise exception
            'migration 045 rollback is unsafe: % V2-only entity IDs already use the shared allocator',
            v2_only_rows;
    end if;
end
$$;

select setval(
    'entities_v2_id_seq',
    greatest(
        (select last_value from entities_v2_id_seq),
        coalesce((select max(id) from entities_v2), 1)
    ),
    true
);

alter table entities_v2
    alter column id set default nextval('entities_v2_id_seq'::regclass);

revoke usage, select on sequence observed_entities_id_seq from adlog_context_worker;

delete from schema_migrations
where version=45 and name='ad_context_shared_entity_identity';

commit;
