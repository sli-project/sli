-- Convert implicit legacy ownership into DML, without widening dedicated-role
-- ACLs on storage/semantic/plugin tables. No DDL or migration-ledger writes.
-- Ownership moves first: privileges granted while adlog_user still owns a
-- relation are owner ACL entries and would move to the new owner with it.
DO $$
DECLARE item record;
BEGIN
    CREATE TEMP TABLE sli_legacy_runtime_relations ON COMMIT DROP AS
        SELECT n.nspname, c.relname, c.relkind
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relowner = 'adlog_user'::regrole
          AND n.nspname = 'public';
    EXECUTE 'REASSIGN OWNED BY adlog_user TO sli_migration';
    FOR item IN SELECT * FROM sli_legacy_runtime_relations
    LOOP
        IF item.relname = 'schema_migrations' THEN
            CONTINUE;
        ELSIF item.relkind IN ('r', 'p') THEN
            EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE %I.%I TO adlog_user', item.nspname, item.relname);
        ELSIF item.relkind IN ('v', 'm') THEN
            EXECUTE format('GRANT SELECT ON TABLE %I.%I TO adlog_user', item.nspname, item.relname);
        ELSIF item.relkind = 'S' THEN
            EXECUTE format('GRANT USAGE, SELECT ON SEQUENCE %I.%I TO adlog_user', item.nspname, item.relname);
        END IF;
    END LOOP;
END $$;
REVOKE CREATE ON SCHEMA public FROM PUBLIC, adlog_user;
REVOKE ALL ON public.schema_migrations FROM adlog_user;
GRANT SELECT ON public.schema_migrations TO adlog_user;
-- Security-definer semantic functions (migration 153) run as the storage owner
-- and read finding_evidence; on a converted legacy DB that table moves to
-- sli_migration above, so the owner role needs the read explicitly.
GRANT SELECT ON public.finding_evidence TO adlog_storage_owner;
