-- Rollback 070 is forbidden while report code uses entity_v2_is_active(bigint).
-- Removing the helper would turn bounded report reads into production errors.
do $$
begin
    raise exception 'rollback 070 is forbidden while bounded identity lookup is in use';
end
$$;
