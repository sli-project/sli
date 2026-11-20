-- Rollback for migration 148: revokes the column grant on domains from the VPN
-- session reader role. Applicable only while 148 is the latest migration.
-- On installations that went through 062 this also removes the grant 062
-- made; re-apply 148 to restore it.

begin;

do $$
begin
  if exists (select 1 from public.schema_migrations where version > 148) then
    raise exception 'rollback 148 requires 148 to be the latest migration';
  end if;
end
$$;

revoke select (id, fqdn) on public.domains from adlog_vpn_session_reader_owner;

delete from schema_migrations where version = 148;

commit;
