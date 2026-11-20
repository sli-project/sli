--
-- PostgreSQL database cluster dump
--



SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;

--
-- Roles
--

CREATE ROLE adlog_administrative_activity_owner;
ALTER ROLE adlog_administrative_activity_owner WITH NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS;
CREATE ROLE adlog_context_worker;
ALTER ROLE adlog_context_worker WITH NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS;
CREATE ROLE adlog_plugin_lifecycle_executor;
ALTER ROLE adlog_plugin_lifecycle_executor WITH NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS;
CREATE ROLE adlog_plugin_lifecycle_owner;
ALTER ROLE adlog_plugin_lifecycle_owner WITH NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS;
CREATE ROLE adlog_plugin_remote_access_owner;
ALTER ROLE adlog_plugin_remote_access_owner WITH NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS;
CREATE ROLE adlog_plugin_remote_access_runtime;
ALTER ROLE adlog_plugin_remote_access_runtime WITH NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS;
CREATE ROLE adlog_radius_accounting_worker;
ALTER ROLE adlog_radius_accounting_worker WITH NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS;
CREATE ROLE adlog_radius_identity_resolver;
ALTER ROLE adlog_radius_identity_resolver WITH NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS;
CREATE ROLE adlog_radius_preflight_reader;
ALTER ROLE adlog_radius_preflight_reader WITH NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS;
CREATE ROLE adlog_radius_session_consumer;
ALTER ROLE adlog_radius_session_consumer WITH NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS;
CREATE ROLE adlog_radius_session_reconciliation_writer;
ALTER ROLE adlog_radius_session_reconciliation_writer WITH NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS;
CREATE ROLE adlog_semantic_worker;
ALTER ROLE adlog_semantic_worker WITH NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS;
CREATE ROLE adlog_storage_drill;
ALTER ROLE adlog_storage_drill WITH NOSUPERUSER INHERIT NOCREATEROLE CREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS;
CREATE ROLE adlog_storage_migrator;
ALTER ROLE adlog_storage_migrator WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS;
CREATE ROLE adlog_storage_owner;
ALTER ROLE adlog_storage_owner WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS;
CREATE ROLE adlog_storage_worker;
ALTER ROLE adlog_storage_worker WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS;
ALTER ROLE adlog_user WITH NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB LOGIN NOREPLICATION NOBYPASSRLS;
CREATE ROLE adlog_vpn_session_reader_owner;
ALTER ROLE adlog_vpn_session_reader_owner WITH NOSUPERUSER NOINHERIT NOCREATEROLE NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS;

--
-- User Configurations
--


--
-- Role memberships
--

GRANT adlog_administrative_activity_owner TO adlog_storage_owner WITH INHERIT TRUE GRANTED BY postgres;
GRANT adlog_plugin_lifecycle_executor TO adlog_storage_owner WITH INHERIT TRUE GRANTED BY postgres;
GRANT adlog_plugin_lifecycle_owner TO adlog_storage_owner WITH INHERIT TRUE GRANTED BY postgres;
GRANT adlog_plugin_remote_access_owner TO adlog_storage_owner WITH INHERIT TRUE GRANTED BY postgres;
GRANT adlog_plugin_remote_access_runtime TO adlog_storage_owner WITH INHERIT TRUE GRANTED BY postgres;
GRANT adlog_radius_accounting_worker TO adlog_storage_owner WITH INHERIT TRUE GRANTED BY postgres;
GRANT adlog_radius_identity_resolver TO adlog_storage_owner WITH INHERIT TRUE GRANTED BY postgres;
GRANT adlog_radius_preflight_reader TO adlog_storage_owner WITH INHERIT TRUE GRANTED BY postgres;
GRANT adlog_radius_session_consumer TO adlog_storage_owner WITH INHERIT TRUE GRANTED BY postgres;
GRANT adlog_radius_session_reconciliation_writer TO adlog_storage_owner WITH INHERIT TRUE GRANTED BY postgres;
GRANT adlog_storage_owner TO adlog_storage_migrator WITH INHERIT TRUE GRANTED BY postgres;
GRANT adlog_user TO adlog_storage_migrator WITH INHERIT TRUE GRANTED BY postgres;
GRANT adlog_vpn_session_reader_owner TO adlog_storage_owner WITH INHERIT TRUE GRANTED BY postgres;





--
-- PostgreSQL database cluster dump complete
--

