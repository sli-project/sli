-- Rollback is fail-closed after source FKs are removed: hot source rows may no
-- longer exist, so recreating the constraints or deleting retained evidence
-- would be unsafe. Repair or reversal must be a separately reviewed forward
-- migration.
do $$
begin
    raise exception 'rollback 071 is forbidden after retention decoupling';
end
$$;
