-- The bundled source pack still emits this exact revision.  Removing its
-- registration would deterministically restore the fail-closed outbox error.
do $$
begin
    raise exception 'rollback 082 is forbidden while the bundled source pack emits 2026-07-30-radius-descriptor-v1; use a separately reviewed forward migration';
end
$$;
