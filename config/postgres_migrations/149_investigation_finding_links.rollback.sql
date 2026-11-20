-- Rollback for migration 149: drops the finding-to-case links.
-- Applicable only while 149 is the latest migration. Links made in the
-- interface are lost; the cases and findings themselves stay.

begin;

do $$
begin
  if exists (select 1 from public.schema_migrations where version > 149) then
    raise exception 'rollback 149 requires 149 to be the latest migration';
  end if;
end
$$;

drop table if exists public.investigation_finding_links;

delete from schema_migrations where version = 149;

commit;
