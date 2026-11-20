-- Migration 097 is intentionally irreversible.
do $$
begin
    raise exception 'migration 097 cannot recreate legacy data; use verified backup restore';
end
$$;
