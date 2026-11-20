-- Rollback for migration 147: drops the domain controller targets table.
-- Targets added in the interface are lost; collection falls back to
-- config/domain_controllers.json (copy the targets there first if needed).

begin;

drop table if exists public.domain_controller_targets;

delete from schema_migrations where version = 147;

commit;
