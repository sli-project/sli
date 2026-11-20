-- Role bootstrap for a later controlled canary. No credentials or LOGIN are set by this file.
-- A launcher may temporarily enable LOGIN for adlog_storage_migrator/drill through a protected secret channel.
DO $$
BEGIN
    IF NOT EXISTS (select 1 from pg_roles where rolname='adlog_storage_owner') THEN
        CREATE ROLE adlog_storage_owner NOLOGIN NOSUPERUSER NOCREATEDB NOBYPASSRLS NOREPLICATION;
    END IF;
    IF NOT EXISTS (select 1 from pg_roles where rolname='adlog_storage_migrator') THEN
        CREATE ROLE adlog_storage_migrator NOLOGIN NOSUPERUSER NOCREATEDB NOBYPASSRLS NOREPLICATION;
    END IF;
    IF NOT EXISTS (select 1 from pg_roles where rolname='adlog_storage_worker') THEN
        CREATE ROLE adlog_storage_worker NOLOGIN NOSUPERUSER NOCREATEDB NOBYPASSRLS NOREPLICATION;
    END IF;
    IF NOT EXISTS (select 1 from pg_roles where rolname='adlog_semantic_worker') THEN
        CREATE ROLE adlog_semantic_worker NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
    END IF;
    IF NOT EXISTS (select 1 from pg_roles where rolname='adlog_storage_drill') THEN
        CREATE ROLE adlog_storage_drill NOLOGIN NOSUPERUSER CREATEDB NOBYPASSRLS NOREPLICATION;
    END IF;
END
$$;
ALTER ROLE adlog_storage_owner NOLOGIN NOSUPERUSER NOCREATEDB NOBYPASSRLS NOREPLICATION;
ALTER ROLE adlog_storage_migrator NOLOGIN NOSUPERUSER NOCREATEDB NOBYPASSRLS NOREPLICATION;
ALTER ROLE adlog_storage_worker NOLOGIN NOSUPERUSER NOCREATEDB NOBYPASSRLS NOREPLICATION;
ALTER ROLE adlog_semantic_worker NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
ALTER ROLE adlog_storage_drill NOLOGIN NOSUPERUSER CREATEDB NOBYPASSRLS NOREPLICATION;
GRANT adlog_storage_owner TO adlog_storage_migrator;
-- The non-login migrator needs the application-owner identity only for the
-- later, explicitly gated FK rebinding migration.  Runtime never inherits the
-- storage roles and the launcher must return this role to NOLOGIN afterwards.
GRANT adlog_user TO adlog_storage_migrator;

-- Least-privilege ownership/bootstrap grants for later canary execution.
GRANT USAGE, CREATE ON SCHEMA public TO adlog_storage_owner;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE schema_migrations TO adlog_storage_owner;
GRANT USAGE, SELECT ON SEQUENCE schema_migrations_id_seq TO adlog_storage_owner;
GRANT SELECT ON TABLE events, observed_entities, event_entity_links TO adlog_storage_owner;
GRANT SELECT ON TABLE events, observed_entities, event_entity_links TO adlog_storage_worker;
