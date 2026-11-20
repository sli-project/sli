-- Executed only on an empty PostgreSQL volume, by the official entrypoint.
-- Read mounted secrets inside PostgreSQL; never interpolate shell/env values.
SET log_statement = 'none';
SET log_min_error_statement = 'panic';
SET log_error_verbosity = 'terse';
\set VERBOSITY terse
SET password_encryption = 'scram-sha-256';
DO $$
DECLARE
    migration_password text := rtrim(pg_read_file('/run/secrets/migration_password'), E'\r\n');
    runtime_password text := rtrim(pg_read_file('/run/secrets/runtime_password'), E'\r\n');
BEGIN
    IF migration_password = '' OR runtime_password = '' THEN
        RAISE EXCEPTION 'empty role secret';
    END IF;
    EXECUTE format('CREATE ROLE sli_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD %L', migration_password);
    EXECUTE format('CREATE ROLE adlog_user LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD %L', runtime_password);
END $$;
ALTER DATABASE sli OWNER TO sli_migration;
REVOKE ALL ON DATABASE sli FROM PUBLIC;
GRANT CONNECT ON DATABASE sli TO adlog_user;
REVOKE ALL ON DATABASE postgres FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO adlog_user;
